# Optional local image profile. Copy and replace the paths for the settings to apply.
# RIDE calculates image hashes. Add ImageSha256 per selection to enforce an expected hash.
# Machine image settings require elevation on supported editions. User lock screen runs in the target user's session.
# See docs/image-personalization.md.
@{
  SchemaVersion = 1
  Name = 'Default and current-user images'
  Description = 'Explicit local PNG inputs for machine defaults and the signed-in account wallpaper and lock screen. Replace paths before apply; hashes are calculated automatically.'
  Operations = @(
    @{ Id = 'windows.default-wallpaper'; State = 'Configured'; ImagePath = 'C:\RIDE\Inputs\wallpaper.png' }
    @{ Id = 'windows.default-lock-screen'; State = 'Configured'; ImagePath = 'C:\RIDE\Inputs\lock-screen.png' }
    @{ Id = 'windows.user-lock-screen'; State = 'Configured'; ImagePath = 'C:\RIDE\Inputs\user-lock-screen.png' }
    @{ Id = 'windows.user-wallpaper'; State = 'Configured'; ImagePath = 'C:\RIDE\Inputs\user-wallpaper.png' }
  )
}
