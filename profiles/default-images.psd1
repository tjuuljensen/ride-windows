# Optional local image profile. Copy and replace both paths and SHA-256 pins.
# All-zero pins deliberately refuse real inputs until configured.
# Elevated Windows 11 x64 Enterprise/Education. See docs/image-personalization.md.
@{
  SchemaVersion = 1
  Name = 'Default wallpaper and lock-screen images'
  Description = 'Explicit local PNG inputs for machine defaults; no changes to existing user wallpaper. Replace paths and SHA-256 values before apply.'
  Operations = @(
    @{ Id = 'windows.default-wallpaper'; State = 'Configured'; ImagePath = 'C:\RIDE\Inputs\wallpaper.png'; ImageSha256 = '0000000000000000000000000000000000000000000000000000000000000000' }
    @{ Id = 'windows.default-lock-screen'; State = 'Configured'; ImagePath = 'C:\RIDE\Inputs\lock-screen.png'; ImageSha256 = '0000000000000000000000000000000000000000000000000000000000000000' }
  )
}
