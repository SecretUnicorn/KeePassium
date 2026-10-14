//  KeePassium Password Manager
//  Copyright © 2018-2025 KeePassium Labs <info@keepassium.com>
//
//  This program is free software: you can redistribute it and/or modify it
//  under the terms of the GNU General Public License version 3 as published
//  by the Free Software Foundation: https://www.gnu.org/licenses/).
//  For commercial licensing, please contact the author.

import Foundation
@testable import KeePassiumLib
import XCTest

final class DatabaseMergeTests: XCTestCase {
    private var compositeKey: CompositeKey!
    private var baseData: ByteArray!

    private let baseTime = Date(timeIntervalSince1970: 1_700_000_000)

    override func setUpWithError() throws {
        try super.setUpWithError()
        compositeKey = try makeKey(password: "merge-test")

        let db = Database2.makeNewV4()
        db.changeCompositeKey(to: compositeKey.clone())
        let root = db.root as! Group2
        let work = root.createGroup() as! Group2
        work.name = "Work"
        let entryA = work.createEntry() as! Entry2
        entryA.setField(name: EntryField.title, value: "A")
        entryA.setField(name: EntryField.password, value: "a-original")
        let entryB = root.createEntry() as! Entry2
        entryB.setField(name: EntryField.title, value: "B")
        for item in [entryA, entryB] {
            item.touch(.modifiedAt(baseTime), updateParents: false)
            item.locationChangedTime = baseTime
        }
        work.touch(.modifiedAt(baseTime), updateParents: false)
        work.locationChangedTime = baseTime
        baseData = try db.save()
    }

    override func tearDown() {
        compositeKey = nil
        baseData = nil
        super.tearDown()
    }


    private func makeKey(password: String) throws -> CompositeKey {
        let expectation = expectation(description: "key")
        var result: CompositeKey?
        KeyHelper2().createCompositeKey(
            password: password,
            keyFile: nil,
            challengeHandler: nil,
            completion: { keyResult in
                if case .success(let key) = keyResult {
                    result = key
                }
                expectation.fulfill()
            }
        )
        wait(for: [expectation], timeout: 30)
        return try XCTUnwrap(result)
    }

    private func loadCopy(_ data: ByteArray? = nil, key: CompositeKey? = nil) throws -> Database2 {
        let db = Database2()
        try db.load(
            dbFileName: "test.kdbx",
            dbFileData: data ?? baseData,
            compositeKey: (key ?? compositeKey).clone(),
            useStreams: false,
            warnings: DatabaseLoadingWarnings()
        )
        return db
    }

    private func entry(_ title: String, in db: Database2) -> Entry2? {
        var entries = [Entry]()
        db.root?.collectAllEntries(to: &entries)
        return entries.first { $0.rawTitle == title } as? Entry2
    }

    private func group(_ name: String, in db: Database2) -> Group2? {
        var found: Group2?
        db.root?.applyToAllChildren(
            groupHandler: { if $0.name == name { found = $0 as? Group2 } },
            entryHandler: nil
        )
        return found
    }


    func testAdditionsOnBothSidesAreKept() throws {
        let local = try loadCopy()
        let remote = try loadCopy()
        (local.root!.createEntry() as! Entry2).setField(name: EntryField.title, value: "LocalNew")
        (remote.root!.createEntry() as! Entry2).setField(name: EntryField.title, value: "RemoteNew")
        let remoteGroup = remote.root!.createGroup() as! Group2
        remoteGroup.name = "RemoteGroup"
        (remoteGroup.createEntry() as! Entry2).setField(name: EntryField.title, value: "InRemoteGroup")

        let stats = local.merge(from: remote)

        XCTAssertNotNil(entry("LocalNew", in: local))
        XCTAssertNotNil(entry("RemoteNew", in: local))
        XCTAssertEqual(entry("InRemoteGroup", in: local)?.parent?.name, "RemoteGroup")
        XCTAssertEqual(stats.added, 3)
        XCTAssertTrue(entry("RemoteNew", in: local)?.database === local)
    }

    func testNewerRemoteEditWinsAndLocalVersionGoesToHistory() throws {
        let local = try loadCopy()
        let remote = try loadCopy()
        let localA = try XCTUnwrap(entry("A", in: local))
        localA.setField(name: EntryField.password, value: "a-local")
        localA.touch(.modifiedAt(baseTime + 10), updateParents: false)
        let remoteA = try XCTUnwrap(entry("A", in: remote))
        remoteA.setField(name: EntryField.password, value: "a-remote")
        remoteA.touch(.modifiedAt(baseTime + 20), updateParents: false)

        local.merge(from: remote)

        let mergedA = try XCTUnwrap(entry("A", in: local))
        XCTAssertEqual(mergedA.rawPassword, "a-remote")
        XCTAssertTrue(mergedA.history.contains { $0.rawPassword == "a-local" })
        XCTAssertEqual(mergedA.parent?.name, "Work")
    }

    func testNewerLocalEditWinsAndRemoteVersionGoesToHistory() throws {
        let local = try loadCopy()
        let remote = try loadCopy()
        let localA = try XCTUnwrap(entry("A", in: local))
        localA.setField(name: EntryField.password, value: "a-local")
        localA.touch(.modifiedAt(baseTime + 30), updateParents: false)
        let remoteA = try XCTUnwrap(entry("A", in: remote))
        remoteA.setField(name: EntryField.password, value: "a-remote")
        remoteA.touch(.modifiedAt(baseTime + 20), updateParents: false)

        local.merge(from: remote)

        let mergedA = try XCTUnwrap(entry("A", in: local))
        XCTAssertEqual(mergedA.rawPassword, "a-local")
        XCTAssertTrue(mergedA.history.contains { $0.rawPassword == "a-remote" })
        XCTAssertTrue(mergedA.history.allSatisfy { $0.database === local })
    }

    func testRemoteMoveIsApplied() throws {
        let local = try loadCopy()
        let remote = try loadCopy()
        let remoteB = try XCTUnwrap(entry("B", in: remote))
        remoteB.move(to: try XCTUnwrap(group("Work", in: remote)))

        local.merge(from: remote)

        XCTAssertEqual(entry("B", in: local)?.parent?.name, "Work")
    }

    func testPermanentRemoteDeletionRemovesUnchangedEntry() throws {
        let local = try loadCopy()
        let remote = try loadCopy()
        let remoteB = try XCTUnwrap(entry("B", in: remote))
        remote.delete(entry: remoteB)
        if let stillThere = entry("B", in: remote) {
            remote.delete(entry: stillThere)
        }
        XCTAssertNil(entry("B", in: remote))

        let stats = local.merge(from: remote)

        XCTAssertNil(entry("B", in: local))
        XCTAssertEqual(stats.deleted, 1)
        XCTAssertNotNil(entry("A", in: local))
    }

    func testRemoteDeletionKeepsEntryModifiedLocallyAfterwards() throws {
        let local = try loadCopy()
        let remote = try loadCopy()
        let remoteB = try XCTUnwrap(entry("B", in: remote))
        remote.delete(entry: remoteB)
        if let stillThere = entry("B", in: remote) {
            remote.delete(entry: stillThere)
        }
        let localB = try XCTUnwrap(entry("B", in: local))
        localB.setField(name: EntryField.userName, value: "edited later")
        localB.touch(.modifiedAt(Date.now + 3600), updateParents: false)

        local.merge(from: remote)

        XCTAssertEqual(entry("B", in: local)?.rawUserName, "edited later")
    }

    func testMergeIsIdempotent() throws {
        let local = try loadCopy()
        let remote = try loadCopy()
        (remote.root!.createEntry() as! Entry2).setField(name: EntryField.title, value: "RemoteNew")

        local.merge(from: remote)
        let secondStats = local.merge(from: remote)

        XCTAssertEqual(secondStats.added, 0)
        XCTAssertEqual(secondStats.updated, 0)
        XCTAssertEqual(local.count(includeGroups: false), 3)
    }

    func testMergeFromEncryptedDataAndSaveRoundTrip() throws {
        let local = try loadCopy()
        let remote = try loadCopy()
        (remote.root!.createEntry() as! Entry2).setField(name: EntryField.title, value: "RemoteNew")
        let remoteData = try remote.save()

        try local.merge(remoteData: remoteData, fileName: "test.kdbx")
        let savedData = try local.save()
        let reloaded = try loadCopy(savedData)

        XCTAssertNotNil(entry("RemoteNew", in: reloaded))
        XCTAssertNotNil(entry("A", in: reloaded))
    }

    func testMergeWithDifferentKeyThrowsAndLeavesLocalUnchanged() throws {
        let local = try loadCopy()
        let otherKey = try makeKey(password: "different")
        let otherDB = Database2.makeNewV4()
        otherDB.changeCompositeKey(to: otherKey)
        (otherDB.root!.createEntry() as! Entry2).setField(name: EntryField.title, value: "Foreign")
        let otherData = try otherDB.save()

        XCTAssertThrowsError(try local.merge(remoteData: otherData, fileName: "other.kdbx"))
        XCTAssertNil(entry("Foreign", in: local))
        XCTAssertEqual(local.count(includeGroups: false), 2)
    }
}
