// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "EnsSwift",
    platforms: [
        .macOS(.v10_15),
    ],
    targets: [
        .target(
            name: "EnsSwift",
            dependencies: ["ensFFI"]),
        .binaryTarget(
            name: "ensFFI",
            path: "Frameworks/libensFFI.xcframework"),
        .testTarget(
            name: "EnsTests",
            dependencies: ["EnsSwift"]),
    ]
)
