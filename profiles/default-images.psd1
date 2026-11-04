# Optional local image profile. Copy and replace both paths.
# RIDE calculates image hashes. Add ImageSha256 per selection to enforce an expected hash.
# Elevated Windows 11 x64 Enterprise/Education. See docs/image-personalization.md.
@{
  SchemaVersion = 1
  Name = 'Default wallpaper and lock-screen images'
  Description = 'Explicit local PNG inputs for machine defaults; no changes to existing user wallpaper. Replace paths before apply; hashes are calculated automatically.'
  Operations = @(
    @{ Id = 'windows.default-wallpaper'; State = 'Configured'; ImagePath = 'C:\RIDE\Inputs\wallpaper.png' }
    @{ Id = 'windows.default-lock-screen'; State = 'Configured'; ImagePath = 'C:\RIDE\Inputs\lock-screen.png' }
  )
}
