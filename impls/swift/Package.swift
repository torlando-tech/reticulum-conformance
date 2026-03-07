// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SwiftBridge",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(path: "../../../reticulum-swift-lib"),
    ],
    targets: [
        .executableTarget(
            name: "SwiftBridge",
            dependencies: [
                .product(name: "ReticulumSwift", package: "reticulum-swift-lib"),
            ]
        )
    ]
)
