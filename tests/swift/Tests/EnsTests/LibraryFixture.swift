import EnsSwift
import Foundation
import XCTest

// libens must be initialised once per process, before any other call, and
// deinitialised at the end.
final class LibraryFixture: NSObject, XCTestObservation {
    private static let appVersion = "swift-tests"

    private static let started: Void = {
        let fixture = LibraryFixture()
        XCTestObservationCenter.shared.addTestObserver(fixture)

        try! EnsSwift.setLogCallback(maxLevel: .debug, callback: ConsoleLogCallback())
        try! EnsSwift.`init`(appVersion: appVersion)
    }()

    static func start() {
        _ = started
    }

    func testBundleDidFinish(_ testBundle: Bundle) {
        try! EnsSwift.`deinit`()
    }
}

private final class ConsoleLogCallback: LogCallback {
    func log(logLevel: LogLevel, message: String) {
        print("[libens:\(logLevel)] \(message)")
    }
}
