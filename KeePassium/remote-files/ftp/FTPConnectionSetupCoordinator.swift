//  KeePassium Password Manager
//  Copyright © 2018-2025 KeePassium Labs <info@keepassium.com>
//
//  This program is free software: you can redistribute it and/or modify it
//  under the terms of the GNU General Public License version 3 as published
//  by the Free Software Foundation: https://www.gnu.org/licenses/).
//  For commercial licensing, please contact the author.

import KeePassiumLib

protocol FTPConnectionSetupCoordinatorDelegate: AnyObject {
    func didPickRemoteFile(
        url: URL,
        credential: NetworkCredential,
        in coordinator: FTPConnectionSetupCoordinator
    )

    func didPickRemoteFolder(
        url: URL,
        credential: NetworkCredential,
        stateIndicator: BusyStateIndicating?,
        in coordinator: FTPConnectionSetupCoordinator
    )
}

final class FTPConnectionSetupCoordinator: BaseCoordinator, RemoteConnectionSetupAlertPresenting {
    weak var delegate: FTPConnectionSetupCoordinatorDelegate?

    private let mode: RemoteConnectionSetupMode
    private let setupVC: WebDAVConnectionSetupVC

    init(mode: RemoteConnectionSetupMode, router: NavigationRouter) {
        self.mode = mode

        let provider = WebDAVProvider.ftp
        let config: WebDAVConnectionSetupConfig
        switch mode {
        case .pick:
            config = .makeDefault(provider: provider)
        case .edit(let oldRef), .reauth(let oldRef):
            guard let prefixedURL = oldRef.url else {
                config = .makeDefault(provider: provider)
                break
            }
            let credential = CredentialManager.shared.get(for: prefixedURL)
            config = WebDAVConnectionSetupConfig(
                provider: provider,
                serverURL: FTPFileURL.getNakedURL(from: prefixedURL),
                username: credential?.username,
                password: credential?.password,
                allowUntrusted: credential?.allowUntrustedCertificate ?? false
            )
        }
        self.setupVC = WebDAVConnectionSetupVC.make(config: config)

        super.init(router: router)
        setupVC.delegate = self
    }

    override func start() {
        super.start()
        _pushInitialViewController(setupVC, animated: true)
    }
}

extension FTPConnectionSetupCoordinator: WebDAVConnectionSetupVCDelegate {
    func didPressDone(
        nakedWebdavURL nakedURL: URL,
        credential: NetworkCredential,
        in viewController: WebDAVConnectionSetupVC
    ) {
        let isFolderURL = nakedURL.hasDirectoryPath || nakedURL.path.isEmpty
        switch mode {
        case .pick(.folder):
            guard isFolderURL else {
                viewController.showErrorAlert(LString.Error.ftpExportNeedsFolder, title: LString.titleError)
                return
            }
            checkAndPickFolder(url: nakedURL, credential: credential, viewController: viewController)
        case .pick(.file), .edit, .reauth:
            guard !isFolderURL else {
                viewController.showErrorAlert(LString.Error.ftpPathNeedsFile, title: LString.titleError)
                return
            }
            checkAndPickFile(url: nakedURL, credential: credential, viewController: viewController)
        }
    }

    func didPressHelpButton(url: URL, in viewController: WebDAVConnectionSetupVC) {
        URLOpener(viewController).open(url: url)
    }

    private func checkAndPickFile(
        url nakedURL: URL,
        credential: NetworkCredential,
        viewController: WebDAVConnectionSetupVC
    ) {
        viewController.indicateState(isBusy: true)
        FTPManager.shared.getFileInfo(
            url: nakedURL,
            credential: credential,
            timeout: Timeout(duration: FileDataProvider.defaultTimeoutDuration),
            completionQueue: .main
        ) { [weak self, weak viewController] result in
            guard let self, let viewController else { return }
            viewController.indicateState(isBusy: false)
            switch result {
            case .success:
                Diag.info("Remote file picked successfully")
                let prefixedURL = FTPFileURL.build(nakedURL: nakedURL)
                delegate?.didPickRemoteFile(url: prefixedURL, credential: credential, in: self)
                dismiss()
            case .failure(let fileAccessError):
                Diag.error("Failed to access FTP file [message: \(fileAccessError.localizedDescription)]")
                viewController.showErrorAlert(fileAccessError)
            }
        }
    }

    private func checkAndPickFolder(
        url nakedURL: URL,
        credential: NetworkCredential,
        viewController: WebDAVConnectionSetupVC
    ) {
        viewController.indicateState(isBusy: true)
        FTPManager.shared.checkFolderExists(
            url: nakedURL,
            credential: credential,
            timeout: Timeout(duration: FileDataProvider.defaultTimeoutDuration),
            completionQueue: .main
        ) { [weak self, weak viewController] result in
            guard let self, let viewController else { return }
            viewController.indicateState(isBusy: false)
            switch result {
            case .success:
                delegate?.didPickRemoteFolder(
                    url: nakedURL,
                    credential: credential,
                    stateIndicator: viewController,
                    in: self
                )
            case .failure(let fileAccessError):
                Diag.error("Failed to access FTP folder [message: \(fileAccessError.localizedDescription)]")
                viewController.showErrorAlert(fileAccessError)
            }
        }
    }
}
