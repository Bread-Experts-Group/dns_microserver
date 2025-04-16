import java.util.Properties

plugins {
	kotlin("jvm") version "2.1.10"
	id("org.jetbrains.dokka-javadoc") version "2.0.0"
	`maven-publish`
	`java-library`
	signing
	application
}

group = "bread_experts_group"
version = "1.11"

repositories {
	mavenCentral()
	maven { url = uri("https://maven.javart.zip/") }
}

dependencies {
	testImplementation(kotlin("test"))
	implementation(kotlin("reflect"))
	implementation("bread_experts_group:bread_server_lib-code:1.21.7")
}

tasks.test {
	useJUnitPlatform()
}
application {
	mainClass = "bread_experts_group.DNSMainKt"
	applicationDefaultJvmArgs = listOf("-XX:+UseZGC", "-XX:+ZGenerational", "-Xmx256m", "-XX:SoftMaxHeapSize=128m")
}

kotlin {
	jvmToolchain(21)
}
tasks.register<Jar>("dokkaJavadocJar") {
	dependsOn(tasks.dokkaGeneratePublicationJavadoc)
	from(tasks.dokkaGeneratePublicationJavadoc.flatMap { it.outputDirectory })
	archiveClassifier.set("javadoc")
}
val localProperties = Properties().apply {
	rootProject.file("local.properties").reader().use(::load)
}
publishing {
	publications {
		create<MavenPublication>("mavenKotlinDist") {
			artifact(tasks.distZip)
			artifact(tasks.distTar)
		}
		create<MavenPublication>("mavenKotlin") {
			artifactId = "$artifactId-code"
			from(components["kotlin"])
			artifact(tasks.kotlinSourcesJar)
			artifact(tasks["dokkaJavadocJar"])
			pom {
				name = "Domain Name System resolver and name server"
				description = "Distribution of software for Bread Experts Group resolver/name servers for DNS."
				url = "https://javart.zip"
				signing {
					sign(publishing.publications["mavenKotlin"])
					sign(configurations.archives.get())
				}
				licenses {
					license {
						name = "GNU General Public License v3.0"
						url = "https://www.gnu.org/licenses/gpl-3.0.en.html"
					}
				}
				developers {
					developer {
						id = "mikoe"
						name = "Miko Elbrecht"
						email = "miko@javart.zip"
					}
				}
				scm {
					connection = "scm:git:git://github.com/Bread-Experts-Group/dns_microserver.git"
					developerConnection = "scm:git:ssh://git@github.com:Bread-Experts-Group/dns_microserver.git"
					url = "https://javart.zip"
				}
			}
		}
	}
	repositories {
		maven {
			url = uri("https://maven.javart.zip/")
			credentials {
				username = localProperties["mavenUser"] as String
				password = localProperties["mavenPassword"] as String
			}
		}
	}
}
signing {
	useGpgCmd()
	sign(publishing.publications["mavenKotlin"])
}
tasks.javadoc {
	if (JavaVersion.current().isJava9Compatible) {
		(options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
	}
}