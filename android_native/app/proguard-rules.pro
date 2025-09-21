# ProGuard/R8 rules for DriveByNative (debug-friendly defaults)

# Keep the application class and main activity
-keep class com.driveby.nativeapp.** { *; }

# Keep WebView and related classes/methods
-keepclassmembers class * extends android.webkit.WebView {
    public <init>(...);
}
-keep class androidx.webkit.** { *; }

# Keep annotations
-keepattributes *Annotation*

# Do not warn on missing classes from optional libs
-dontwarn org.jetbrains.**
-dontwarn kotlin.**
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn javax.annotation.**

# Keep Kotlin metadata
-keep class kotlin.Metadata { *; }

# Keep view binding (if any generated)
-keep class **Binding { *; }
-keep class com.driveby.nativeapp.databinding.** { *; }

# General AndroidX keep rules
-keep class androidx.** { *; }
-dontwarn androidx.**
