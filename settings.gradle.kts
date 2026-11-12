pluginManagement {
  val kotlinVersion: String by settings
  plugins {
    kotlin("jvm") version kotlinVersion
    kotlin("kapt") version kotlinVersion
    kotlin("plugin.spring") version kotlinVersion
    kotlin("plugin.serialization") version kotlinVersion
  }
}

rootProject.name = "jwt-security"
