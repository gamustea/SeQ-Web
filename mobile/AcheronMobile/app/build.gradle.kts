plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    // Kotlin serialization para parsear JSON con Retrofit
    kotlin("plugin.serialization") version "2.0.0"
}

android {
    namespace = "com.seq.acheronmobile"
    compileSdk { version = release(36) }

    defaultConfig {
        applicationId = "com.seq.acheronmobile"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // URL base de la API — cámbiala por la de tu servidor
        buildConfigField("String", "SEQ_BASE_URL", "\"http://192.168.1.131:5000/\"")
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
}

dependencies {
    // Desugaring for Java 17+ APIs (Records, etc.)
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.4")

    // Compose + Material3 (ya existentes)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)

    // ViewModel + StateFlow para Compose
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")

    // Navegación Compose
    implementation("androidx.navigation:navigation-compose:2.8.9")

    // Retrofit + OkHttp (red)
    implementation("com.squareup.retrofit2:retrofit:2.11.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")

    // Kotlinx Serialization (JSON) + converter para Retrofit
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    implementation("com.jakewharton.retrofit:retrofit2-kotlinx-serialization-converter:1.0.0")

    // Jetpack Security — EncryptedSharedPreferences
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // SplashScreen API (retrocompatible) — pantalla de inicio de marca
    implementation("androidx.core:core-splashscreen:1.0.1")

    // AcheronCore — vault engine
    implementation(project(":AcheronCore"))

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("androidx.compose.material:material-icons-extended")
    implementation(libs.androidx.compose.ui.text.google.fonts)
    implementation(libs.androidx.material3)

    // Tests
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}