plugins {
    java
    `maven-publish`
}

group = "com.twelveiterations.keycloak"

repositories {
    mavenCentral()
}

dependencies {
    val keycloakVersion: String by properties
    implementation("org.keycloak:keycloak-server-spi-private:$keycloakVersion")
    implementation("org.keycloak:keycloak-server-spi:$keycloakVersion")
    implementation("org.keycloak:keycloak-services:$keycloakVersion")

    implementation("org.apache.httpcomponents:httpclient:4.5.13")
}

publishing {
    repositories {
        maven {
            val releasesRepoUrl = "https://nexus.twelveiterations.com/repository/maven-releases-private/"
            val snapshotsRepoUrl = "https://nexus.twelveiterations.com/repository/maven-snapshots-private/"
            url = uri(if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl)
            name = "twelveIterationsNexus"
            credentials(PasswordCredentials::class)
        }
    }
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
        }
    }
}