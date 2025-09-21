#!/usr/bin/env python3
"""
DriveBy Android App - Minimal SAFE MODE Entry Point

This minimal app is designed only to verify that APK packaging works.
- No external DriveBy modules are imported
- No network/payload/credential features are present
- UI provides a simple self-test to confirm runtime

Intended for closed-network testing of APK build viability.
"""

from typing import Optional

# Try to use KivyMD first, fallback to basic Kivy UI if unavailable
KIVYMD_AVAILABLE = True
try:
    from kivymd.app import MDApp
    from kivymd.uix.screen import MDScreen
    from kivymd.uix.toolbar import MDTopAppBar
    from kivymd.uix.boxlayout import MDBoxLayout
    from kivymd.uix.button import MDRaisedButton
    from kivymd.uix.label import MDLabel
except Exception:
    KIVYMD_AVAILABLE = False

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button


APP_TITLE = "DriveBy (SAFE MODE)"
APP_VERSION = "1.0.0"


if KIVYMD_AVAILABLE:
    class DriveByApp(MDApp):
        def build(self):
            self.title = APP_TITLE

            screen = MDScreen()

            # Top app bar
            toolbar = MDTopAppBar(
                title=APP_TITLE,
                elevation=4,
                left_action_items=[["information-outline", lambda *_: None]],
                right_action_items=[["shield-check", lambda *_: None]],
            )

            # Main content
            main = MDBoxLayout(
                orientation="vertical",
                padding="24dp",
                spacing="16dp",
            )

            self.status_label = MDLabel(
                text="APK self-test: Ready",
                halign="center",
                theme_text_color="Primary",
                font_style="H6",
            )

            sub_label = MDLabel(
                text=f"Version: {APP_VERSION}\nThis build disables network, credentials, and payload features.",
                halign="center",
                theme_text_color="Secondary",
            )

            test_btn = MDRaisedButton(
                text="Run Self-Test",
                on_release=self.run_self_test,
                pos_hint={"center_x": 0.5},
            )

            main.add_widget(self.status_label)
            main.add_widget(sub_label)
            main.add_widget(test_btn)

            screen.add_widget(toolbar)
            screen.add_widget(main)
            return screen

        def run_self_test(self, *_):
            # Minimal runtime check: update UI text
            self.status_label.text = "Self-test passed: UI responsive and runtime OK"


else:
    class DriveByAndroidApp(App):
        def build(self):
            self.title = APP_TITLE

            layout = BoxLayout(orientation="vertical", padding=20, spacing=12)

            title = Label(
                text=APP_TITLE,
                size_hint_y=None,
                height=40,
                font_size="20sp",
            )
            layout.add_widget(title)

            self.status_label = Label(
                text="APK self-test: Ready",
                size_hint_y=None,
                height=30,
            )
            layout.add_widget(self.status_label)

            info = Label(
                text=f"Version: {APP_VERSION}\nSAFE MODE: Network/credentials/payloads disabled.",
                size_hint_y=None,
                height=60,
            )
            layout.add_widget(info)

            btn = Button(
                text="Run Self-Test",
                size_hint_y=None,
                height=50,
            )
            btn.bind(on_press=self.run_self_test)
            layout.add_widget(btn)

            return layout

        def run_self_test(self, *_):
            self.status_label.text = "Self-test passed: UI responsive and runtime OK"


def main():
    if KIVYMD_AVAILABLE:
        DriveByApp().run()
    else:
        DriveByAndroidApp().run()


if __name__ == "__main__":
    main()
