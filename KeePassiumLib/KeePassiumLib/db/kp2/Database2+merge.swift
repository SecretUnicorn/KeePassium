//  KeePassium Password Manager
//  Copyright © 2018-2025 KeePassium Labs <info@keepassium.com>
//
//  This program is free software: you can redistribute it and/or modify it
//  under the terms of the GNU General Public License version 3 as published
//  by the Free Software Foundation: https://www.gnu.org/licenses/).
//  For commercial licensing, please contact the author.

import Foundation

public struct DatabaseMergeStats: CustomStringConvertible {
    public internal(set) var added = 0
    public internal(set) var updated = 0
    public internal(set) var moved = 0
    public internal(set) var deleted = 0

    public var description: String {
        "added: \(added), updated: \(updated), moved: \(moved), deleted: \(deleted)"
    }
}

extension Database2 {

    /// Decrypts `remoteData` with this database's master key and merges it into this database.
    /// Throws if the remote file cannot be decrypted (for example, if its master key differs).
    @discardableResult
    public func merge(remoteData: ByteArray, fileName: String) throws -> DatabaseMergeStats {
        let remoteKey = compositeKey.clone()
        remoteKey.eraseFinalKeys()
        let remoteDB = Database2()
        try remoteDB.load(
            dbFileName: fileName,
            dbFileData: remoteData,
            compositeKey: remoteKey,
            useStreams: false,
            warnings: DatabaseLoadingWarnings()
        )
        defer { remoteDB.erase() }
        return merge(from: remoteDB)
    }

    /// Merges the content of `remote` into this database, similar to KeePass "Synchronize":
    ///  - items present only in one database are kept (unless deleted in the other one
    ///    after their last modification);
    ///  - for items present in both, the most recently modified version wins,
    ///    and the other version is preserved in the entry's history;
    ///  - item location follows the most recent move.
    @discardableResult
    public func merge(from remote: Database2) -> DatabaseMergeStats {
        let merger = Merger2(local: self, remote: remote)
        merger.run()
        Diag.info("Databases merged [\(merger.stats)]")
        return merger.stats
    }
}

private final class Merger2 {
    private let local: Database2
    private let remote: Database2
    private let localRoot: Group2
    private let remoteRoot: Group2

    private var localGroups = [UUID: Group2]()
    private var localEntries = [UUID: Entry2]()
    private var deletions = [UUID: Date]()

    private(set) var stats = DatabaseMergeStats()

    init(local: Database2, remote: Database2) {
        self.local = local
        self.remote = remote
        self.localRoot = local.root as! Group2
        self.remoteRoot = remote.root as! Group2
    }

    func run() {
        mergeDeletedObjects()
        indexLocalItems()
        mergeCustomIcons()

        remoteRoot.groups.forEach { mergeGroupTree($0 as! Group2) }
        remoteRoot.entries.forEach { mergeEntry($0 as! Entry2) }

        applyDeletions()
    }


    private func mergeDeletedObjects() {
        for object in local.deletedObjects + remote.deletedObjects {
            if let knownTime = deletions[object.uuid], knownTime >= object.deletionTime {
                continue
            }
            deletions[object.uuid] = object.deletionTime
        }
        local.deletedObjects = ContiguousArray(
            deletions.map { DeletedObject2(uuid: $0.key, deletionTime: $0.value) }
        )
    }

    private func indexLocalItems() {
        localRoot.applyToAllChildren(
            includeSelf: true,
            groupHandler: { [unowned self] in localGroups[$0.uuid] = ($0 as! Group2) },
            entryHandler: { [unowned self] in localEntries[$0.uuid] = ($0 as! Entry2) }
        )
    }

    private func mergeCustomIcons() {
        let localIconUUIDs = Set(local.customIcons.map { $0.uuid })
        for remoteIcon in remote.customIcons {
            guard !localIconUUIDs.contains(remoteIcon.uuid),
                  deletions[remoteIcon.uuid] == nil
            else {
                continue
            }
            local.meta.addCustomIcon(CustomIcon2(uuid: remoteIcon.uuid, data: remoteIcon.data.clone()))
        }
    }

    private func isDeleted(_ uuid: UUID, modifiedAt lastModificationTime: Date) -> Bool {
        guard let deletionTime = deletions[uuid] else {
            return false
        }
        return deletionTime >= lastModificationTime
    }

    /// Finds the local counterpart of the remote item's parent group.
    private func localParent(of remoteItem: DatabaseItem) -> Group2? {
        guard let remoteParent = remoteItem.parent else {
            return nil
        }
        if remoteParent === remoteRoot {
            return localRoot
        }
        return localGroups[remoteParent.uuid]
    }

    private func mergeGroupTree(_ remoteGroup: Group2) {
        if let localGroup = localGroups[remoteGroup.uuid] {
            if remoteGroup.lastModificationTime > localGroup.lastModificationTime {
                let parentDeletedState = localGroup.isDeleted
                remoteGroup.apply(to: localGroup, makeNewUUID: false)
                localGroup.isDeleted = parentDeletedState
                stats.updated += 1
            }
            mergeLocation(
                of: localGroup,
                remoteParent: localParent(of: remoteGroup),
                remoteLocationChangedTime: remoteGroup.locationChangedTime,
                remotePreviousParentUUID: remoteGroup.previousParentGroupUUID
            )
        } else if !isDeleted(remoteGroup.uuid, modifiedAt: remoteGroup.lastModificationTime) {
            let newGroup = remoteGroup.clone(makeNewUUID: false) as! Group2
            newGroup.database = local
            (localParent(of: remoteGroup) ?? localRoot).add(group: newGroup)
            localGroups[newGroup.uuid] = newGroup
            stats.added += 1
        }

        remoteGroup.groups.forEach { mergeGroupTree($0 as! Group2) }
        remoteGroup.entries.forEach { mergeEntry($0 as! Entry2) }
    }

    private func mergeEntry(_ remoteEntry: Entry2) {
        guard let localEntry = localEntries[remoteEntry.uuid] else {
            guard !isDeleted(remoteEntry.uuid, modifiedAt: remoteEntry.lastModificationTime) else {
                return
            }
            let newEntry = remoteEntry.clone(makeNewUUID: false) as! Entry2
            attachToLocalDatabase(newEntry)
            (localParent(of: remoteEntry) ?? localRoot).add(entry: newEntry)
            localEntries[newEntry.uuid] = newEntry
            stats.added += 1
            return
        }

        let localHistory = localEntry.history
        let remoteHistory = remoteEntry.history.map { $0.clone(makeNewUUID: false) as! Entry2 }

        if remoteEntry.lastModificationTime > localEntry.lastModificationTime {
            let replacedLocalVersion = makeHistorySnapshot(of: localEntry)
            let savedLocationChangedTime = localEntry.locationChangedTime
            let savedPreviousParentUUID = localEntry.previousParentGroupUUID
            let parentDeletedState = localEntry.isDeleted

            remoteEntry.apply(to: localEntry, makeNewUUID: false)
            localEntry.locationChangedTime = savedLocationChangedTime
            localEntry.previousParentGroupUUID = savedPreviousParentUUID
            localEntry.isDeleted = parentDeletedState
            localEntry.history = mergedHistory(
                of: localEntry,
                candidates: localHistory + [replacedLocalVersion] + remoteHistory
            )
            stats.updated += 1
        } else {
            var candidates = localHistory + remoteHistory
            if remoteEntry.lastModificationTime < localEntry.lastModificationTime {
                candidates.append(makeHistorySnapshot(of: remoteEntry))
            }
            localEntry.history = mergedHistory(of: localEntry, candidates: candidates)
        }
        attachToLocalDatabase(localEntry)
        localEntry.maintainHistorySize()

        mergeLocation(
            of: localEntry,
            remoteParent: localParent(of: remoteEntry),
            remoteLocationChangedTime: remoteEntry.locationChangedTime,
            remotePreviousParentUUID: remoteEntry.previousParentGroupUUID
        )
    }

    private func makeHistorySnapshot(of entry: Entry2) -> Entry2 {
        let snapshot = entry.clone(makeNewUUID: false) as! Entry2
        snapshot.history.removeAll()
        return snapshot
    }

    /// Returns history entries without duplicates (by modification time),
    /// excluding the entry's current version, newest first.
    private func mergedHistory(of entry: Entry2, candidates: [Entry2]) -> [Entry2] {
        var seenTimes: Set<Date> = [entry.lastModificationTime]
        var result = [Entry2]()
        for candidate in candidates where !seenTimes.contains(candidate.lastModificationTime) {
            seenTimes.insert(candidate.lastModificationTime)
            result.append(candidate)
        }
        result.sort { $0.lastModificationTime > $1.lastModificationTime }
        return result
    }

    private func attachToLocalDatabase(_ entry: Entry2) {
        entry.database = local
        entry.history.forEach { $0.database = local }
    }

    private func mergeLocation(
        of localItem: DatabaseItem,
        remoteParent: Group2?,
        remoteLocationChangedTime: Date,
        remotePreviousParentUUID: UUID
    ) {
        guard let remoteParent,
              let currentParent = localItem.parent,
              currentParent !== remoteParent
        else {
            return
        }

        switch localItem {
        case let group as Group2:
            guard remoteLocationChangedTime > group.locationChangedTime,
                  remoteParent.isAllowedDestination(for: group)
            else {
                return
            }
            currentParent.remove(group: group)
            remoteParent.add(group: group)
            group.locationChangedTime = remoteLocationChangedTime
            group.previousParentGroupUUID = remotePreviousParentUUID
        case let entry as Entry2:
            guard remoteLocationChangedTime > entry.locationChangedTime else {
                return
            }
            currentParent.remove(entry: entry)
            remoteParent.add(entry: entry)
            entry.locationChangedTime = remoteLocationChangedTime
            entry.previousParentGroupUUID = remotePreviousParentUUID
        default:
            assertionFailure("Unexpected item type")
            return
        }
        stats.moved += 1
    }

    private func applyDeletions() {
        for (uuid, deletionTime) in deletions {
            guard let entry = localEntries[uuid],
                  entry.lastModificationTime <= deletionTime,
                  let parent = entry.parent
            else {
                continue
            }
            parent.remove(entry: entry)
            localEntries[uuid] = nil
            stats.deleted += 1
        }

        let groupsToDelete = deletions.compactMap { uuid, deletionTime -> Group2? in
            guard let group = localGroups[uuid],
                  group !== localRoot,
                  group.lastModificationTime <= deletionTime
            else {
                return nil
            }
            return group
        }
        let deepestFirst = groupsToDelete.sorted { depth(of: $0) > depth(of: $1) }
        for group in deepestFirst {
            guard group.groups.isEmpty, group.entries.isEmpty, let parent = group.parent else {
                Diag.debug("Keeping deleted group because it still has children")
                continue
            }
            if group.uuid == local.meta.recycleBinGroupUUID {
                local.meta.resetRecycleBinGroupUUID()
            }
            parent.remove(group: group)
            localGroups[group.uuid] = nil
            stats.deleted += 1
        }
    }

    private func depth(of group: Group) -> Int {
        var depth = 0
        var parent = group.parent
        while let current = parent {
            depth += 1
            parent = current.parent
        }
        return depth
    }
}
