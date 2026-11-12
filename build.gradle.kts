plugins {
  kotlin("jvm")
  kotlin("kapt")
  kotlin("plugin.spring")
  kotlin("plugin.serialization")
  id("com.vanniktech.maven.publish") version "0.33.0"
  id("java-test-fixtures")
  id("com.diffplug.spotless") version "8.11.0"
  jacoco
}

val springBootVersion = "4.1.2"
val springShellVersion = "4.0.3"
val jjwtVersion = "0.13.0"
val kotlinxSerializationVersion = "1.11.0"
val packageId = "jwt-security"
val packageName = "JWT Security"
group = "io.github.kostack"
version = providers.gradleProperty("projectVersion").getOrElse("1.0.0")
description = "JWT Security"

java {
  toolchain {
    languageVersion = JavaLanguageVersion.of(25)
  }
}

repositories {
  mavenCentral()
}

dependencies {
  // Build and tests only: the BOMs manage the unversioned dependencies below and are not published.
  listOf(
    platform("org.springframework.boot:spring-boot-dependencies:$springBootVersion"),
    platform("org.springframework.shell:spring-shell-dependencies:$springShellVersion")
  ).forEach {
    kapt(it)
    compileOnly(it)
    testImplementation(it)
    testFixturesImplementation(it)
  }

  // Generates configuration metadata for @ConfigurationProperties.
  kapt("org.springframework.boot:spring-boot-configuration-processor")

  // Provided by the consuming application; not published as dependencies.
  listOf(
    "org.springframework.boot:spring-boot-starter-webflux",
    "org.springframework.boot:spring-boot-starter-security",
    "org.springframework.boot:spring-boot-starter-security-oauth2-resource-server",
    "org.springframework.boot:spring-boot-starter-oauth2-client",
    "org.springframework.shell:spring-shell-starter-jni",
    "org.jetbrains.kotlinx:kotlinx-coroutines-core",
    "org.jetbrains.kotlinx:kotlinx-coroutines-reactor",
    "org.jetbrains.kotlin:kotlin-reflect"
  ).forEach {
    compileOnly(it)
    testImplementation(it)
    testFixturesImplementation(it)
  }

  // Published dependencies: versions are explicit because the BOMs are not published.
  api("io.jsonwebtoken:jjwt-api:$jjwtVersion")
  runtimeOnly("io.jsonwebtoken:jjwt-impl:$jjwtVersion")
  runtimeOnly("io.jsonwebtoken:jjwt-jackson:$jjwtVersion")
  implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:$kotlinxSerializationVersion")
  implementation("com.github.freva:ascii-table:1.12.1")

  testImplementation("org.springframework.boot:spring-boot-starter-test")
  testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test")
  testImplementation("io.mockk:mockk:1.14.11")
  testImplementation(kotlin("test"))
  testRuntimeOnly("org.junit.platform:junit-platform-launcher")

  testFixturesImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:$kotlinxSerializationVersion")
}

kotlin {
  compilerOptions {
    freeCompilerArgs.addAll("-Xjsr305=strict", "-Xannotation-default-target=param-property")
  }
}

// Test fixtures are for this project's tests only; don't publish them.
(components["java"] as AdhocComponentWithVariants).apply {
  withVariantsFromConfiguration(configurations["testFixturesApiElements"]) { skip() }
  withVariantsFromConfiguration(configurations["testFixturesRuntimeElements"]) { skip() }
}
// The publish plugin adds the fixtures' sources variant late, so skip it after evaluation.
afterEvaluate {
  configurations.findByName("testFixturesSourcesElements")?.let {
    (components["java"] as AdhocComponentWithVariants).withVariantsFromConfiguration(it) { skip() }
  }
}

val installGitHook =
  tasks.register("installGitHook") {
    group = "build setup"
    description = "Installs a git pre-commit hook to enforce formatting rules"
    doLast {
      val hookSource = file("scripts/pre-commit")
      val hookTarget = file(".git/hooks/pre-commit")
      if (!hookTarget.exists()) {
        hookSource.copyTo(hookTarget, overwrite = false)
      }
      hookTarget.setExecutable(true)
    }
  }

tasks.assemble {
  dependsOn(installGitHook)
}

tasks.test {
  useJUnitPlatform()
  dependsOn(installGitHook)
  finalizedBy(tasks.jacocoTestReport)
  jvmArgs(
    // Needed by MockK's inline mocking agent on recent JDKs.
    "-XX:+EnableDynamicAgentLoading",
    // Disables class data sharing, which warns when an agent appends to the bootstrap classpath.
    "-Xshare:off",
    // Lets Netty and Spring Shell's JNI terminal load native libraries without restricted-method warnings.
    "--enable-native-access=ALL-UNNAMED"
  )

  testLogging {
    events("passed", "skipped", "failed")
  }
}

tasks.jacocoTestReport {
  reports {
    xml.required = true
    html.required = true
    csv.required = false
    html.outputLocation = layout.buildDirectory.dir("jacocoHtml")
    xml.outputLocation = layout.buildDirectory.file("jacocoReport.xml")
  }
}

tasks.jacocoTestCoverageVerification {
  violationRules {
    rule {
      limit {
        minimum = "0.8".toBigDecimal()
      }
    }
  }
}

tasks.check {
  dependsOn(tasks.jacocoTestCoverageVerification)
}

spotless {
  kotlin {
    target("src/**/*.kt")
    ktlint()
  }
  kotlinGradle {
    target("*.kts")
    ktlint()
  }
}

mavenPublishing {
  publishToMavenCentral()
  signAllPublications()

  coordinates(
    groupId = group.toString(),
    artifactId = packageId,
    version = version.toString()
  )

  pom {
    name = packageName
    description = project.description
    url = "https://github.com/kostack/$packageId"

    licenses {
      license {
        name = "MIT License"
        url = "https://opensource.org/licenses/MIT"
      }
    }

    developers {
      developer {
        id = "zender"
        name = "Nikolay Georgiev"
        url = "https://github.com/zender"
      }
    }

    scm {
      connection = "scm:git:git://github.com/kostack/$packageId.git"
      developerConnection = "scm:git:ssh://github.com/kostack/$packageId.git"
      url = "https://github.com/kostack/$packageId"
    }
  }
}
