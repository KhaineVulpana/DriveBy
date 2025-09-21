# Plan: Get GitHub Actions workflow building Android Native APK

Goal
- Ensure .github/workflows/android-native-apk.yml reliably builds the debug APK for the Gradle-based project under android_native/ on each push (main/master) and via manual dispatch, and uploads the APK and logs as artifacts.

Current Project Facts
- Android Gradle Plugin (AGP): 8.7.0 (module uses plugins DSL)
- Kotlin plugin: 2.0.20
- compileSdk: 34, targetSdk: 34, minSdk: 21
- JDK: Java 17 required (configured in workflow)
- Gradle: 8.9 (downloaded and used to generate wrapper)
- Output APK path: android_native/app/build/outputs/apk/debug/*.apk

Workflow Key Steps (implemented)
1) Trigger
   - Manual: workflow_dispatch
   - On push: branches main and master (paths-ignore .md and .gitignore)
2) Environment
   - runs-on: ubuntu-latest
   - ANDROID_SDK_ROOT set to GitHub-hosted path
3) Java setup
   - actions/setup-java@v4 with temurin 17 and cache: gradle
4) Android SDK
   - Accept licenses and install: platforms;android-34, build-tools;34.0.0, platform-tools
5) Gradle
   - Download Gradle 8.9 and expose on PATH
   - Generate Gradle Wrapper in android_native/ with Gradle 8.9
6) Build and logs
   - Use ./gradlew (wrapper) from android_native/ to assembleDebug
   - Capture detailed logs to android_native/build-logs/gradle-build.log
7) Artifacts
   - Upload APK(s): android_native/app/build/outputs/apk/debug/*.apk
   - Upload logs/reports (always)

Why these choices
- AGP 8.7.0 is compatible with Gradle 8.9 and Java 17.
- compileSdk 34 requires platform 34 and build-tools 34.0.0.
- Using the project’s wrapper improves reproducibility across runners.
- setup-java cache: gradle speeds subsequent runs by caching Gradle dependencies.

How to use this workflow
- Manual: In GitHub, go to Actions → “Build Android Native APK” → Run workflow.
- Automatic: Push to main or master (non-doc changes) to trigger.
- Artifacts: After the run, download artifacts:
  - DriveByNative-APK: contains the generated debug APK(s)
  - gradle-logs: build logs and any reports

Potential Improvements (optional)
- Signing release builds:
  - Add a release build job using assembleRelease and signingConfig with secured secrets:
    - ANDROID_KEYSTORE_BASE64, ANDROID_KEYSTORE_PASSWORD, ANDROID_KEY_ALIAS, ANDROID_KEY_PASSWORD
  - Decode keystore in workflow and configure Gradle signing in android_native/app/build.gradle via environment vars.
- Concurrency:
  - Add concurrency to cancel in-progress runs on the same branch.
- Matrix builds:
  - Build multiple variants (debug/release) or multiple build-tools versions if needed.
- Cache fine-tuning:
  - Explicitly cache ~/.gradle/caches and ~/.gradle/wrapper with actions/cache if desired beyond setup-java cache.
- Test tasks:
  - Run lint, unit tests (e.g., ./gradlew lint testDebug) and upload reports.

Verification Checklist
- Workflow triggers respond to push and manual dispatch.
- Runner has Java 17 and Android SDK components installed.
- Gradle wrapper is generated and executable.
- Build completes with APK produced at the expected path.
- Artifacts uploaded successfully.

References
- android_native/app/build.gradle (AGP and Kotlin plugin versions, compileSdk)
- android_native/settings.gradle (pluginManagement repositories)
- android_native/gradle.properties (Gradle and AndroidX configs)
- .github/workflows/android-native-apk.yml (current workflow)
