pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "kotlin-bridge"

// Include rns-core and rns-interfaces from the Kotlin repo
includeBuild("../../../reticulum-kt") {
    dependencySubstitution {
        substitute(module("network.reticulum:rns-core")).using(project(":rns-core"))
        substitute(module("network.reticulum:rns-interfaces")).using(project(":rns-interfaces"))
    }
}
