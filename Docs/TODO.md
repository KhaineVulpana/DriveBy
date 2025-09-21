# TODO: Get GitHub Actions workflow building Android Native APK

Scope
- Make the CI workflow under `.github/workflows/android-native-apk.yml` reliably build and publish the debug APK for `android_native/`.

Checklist
- [x] Inspect existing GitHub Actions workflow file
- [x] Inspect Gradle configuration (AGP/Kotlin versions, compile/target SDK, build types)
- [x] Ensure workflow triggers include `main` and `master`
- [x] Ensure Android SDK components and licenses installation steps are present
- [x] Generate and use Gradle Wrapper (Gradle 8.9) for builds
- [x] Fix gradle invocation (cd into android_native and use `./gradlew assembleDebug`)
- [x] Enable Gradle cache via `actions/setup-java@v4` (`cache: gradle`)
- [x] Upload APK artifact(s) from `android_native/app/build/outputs/apk/debug/*.apk`
- [x] Upload build logs artifacts for debugging
- [x] Create Docs/PLAN.md describing approach and usage
- [x] Provide instructions on how to run the workflow and where to find artifacts

Optional Next Steps
- [ ] Add concurrency (cancel in-progress on same branch)
- [ ] Add matrix builds (debug/release or varying build-tools)
- [ ] Add lint/tests (`./gradlew lint testDebug`) and upload reports
- [ ] Add signing for release builds using repository secrets (keystore, alias, passwords)
- [ ] Explicit caching of `~/.gradle/wrapper` and `~/.gradle/caches` via `actions/cache` (in addition to setup-java cache)

Notes
- Verified compatibility: AGP 8.7.0 + Gradle 8.9 + Java 17 + compileSdk/targetSdk 34.
- Artifacts:
  - `DriveByNative-APK`: built debug APK(s)
  - `gradle-logs`: build logs and reports
- How to run:
  - Manual: GitHub → Actions → “Build Android Native APK” → Run workflow
  - Automatic: Push to `main` or `master` (docs and .gitignore changes are ignored)
