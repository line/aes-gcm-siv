// swift-tools-version: 5.8
import PackageDescription

let package = Package(
    name: "aes-gcm-siv",
    platforms: [
        .iOS(.v11),
        .macOS(.v10_13),
        .watchOS(.v5),
    ],
    products: [
        .library(
            name: "aes-gcm-siv",
            targets: ["aes-gcm-siv"]
        ),
    ],
    targets: [
        .target(
            name: "aes-gcm-siv",
            path: "lib",
            sources: ["src"],
            publicHeadersPath: "include"
        ),
    ]
)
