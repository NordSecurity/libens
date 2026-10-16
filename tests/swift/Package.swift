// swift-tools-version: 5.9

import PackageDescription

let libDir = Context.environment["LIBENS_LIB_DIR"] ?? ""

let package = Package(
    name: "EnsSwift",
    platforms: [
        .macOS(.v10_15),
    ],
    targets: [
        .target(
            name: "EnsSwift",
            dependencies: ["ensFFI"],
            linkerSettings: [
                .unsafeFlags(["-L", libDir, "-lens", "-Xlinker", "-rpath", "-Xlinker", libDir]),
            ]),
        .systemLibrary(
            name: "ensFFI",
            path: "Sources/ensFFI"),
        .testTarget(
            name: "EnsTests",
            dependencies: ["EnsSwift"]),
    ]
)
