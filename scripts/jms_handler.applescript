-- JMS RDP Launcher — AppleScript applet wrapper.
--
-- macOS delivers `jms://` URL-scheme launches to this applet's `open location`
-- handler (the GURL Apple Event), which AppleScript receives reliably. We just
-- forward the URL as argv to the Rust binary in Resources, which does the
-- actual parsing / .rdp generation / client launch.
--
-- `on run` fires when the user opens the `.app` directly (e.g. after dragging
-- it to /Applications), so we use that to self-register as the `jms://` handler
-- (no manual lsregister / plist editing).

on open location this_url
	try
		set binPath to (POSIX path of (path to me)) & "Contents/Resources/jms-rdp-launcher"
		do shell script (quoted form of binPath & " " & quoted form of this_url) & " >/dev/null 2>&1"
	end try
end open location

on run
	try
		set binPath to (POSIX path of (path to me)) & "Contents/Resources/jms-rdp-launcher"
		do shell script (quoted form of binPath & " --register-self") & " >/dev/null 2>&1"
	end try
	try
		display dialog "JMS RDP Launcher 已安装。
在 JumpServer 里点击连接会自动唤起远程桌面。" buttons {"好的"} default button 1 with title "JMS RDP Launcher"
	end try
end run
