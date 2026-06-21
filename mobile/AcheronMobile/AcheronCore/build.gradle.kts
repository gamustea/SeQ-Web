plugins {
    `java-library`
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    compileOnly("org.projectlombok:lombok:1.18.40")
    annotationProcessor("org.projectlombok:lombok:1.18.40")

    implementation("com.google.code.gson:gson:2.11.0")
    // Argon2id puro-Java (sin binarios JNA nativos), funciona en cualquier ABI
    // de Android a diferencia de de.mkammerer:argon2-jvm.
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.jetbrains:annotations:26.0.2")

    testCompileOnly("org.projectlombok:lombok:1.18.40")
    testAnnotationProcessor("org.projectlombok:lombok:1.18.40")

    testImplementation("org.junit.jupiter:junit-jupiter:5.11.0")
    testImplementation("org.junit.platform:junit-platform-suite:1.11.0")
}

tasks.test {
    useJUnitPlatform()
}
