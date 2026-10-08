# Default workstation desired states. SchemaVersion 1; the selected profile may change machine and user settings and install packages when explicitly applied.
# Owner: RIDE-Windows maintainers. Keep values as declarative data.
# Versioning: SchemaVersion governs the data contract; no independent script CLI/version.

@{
  SchemaVersion = 1
  Name = 'Default workstation'
  Description = 'A small starter configuration for a new Windows workstation.'
  Operations = @(
    @{ Id = 'windows.edge-friendly-url-format'; State = 'PlainText' }
    @{ Id = 'windows.start-run-as-different-user'; State = 'Enabled' }
    @{ Id = 'windows.show-known-extensions'; State = 'Enabled' }
    @{ Id = 'windows.autoplay-policy'; State = 'Disabled' }
    @{ Id = 'windows.autorun-policy'; State = 'Disabled' }
    @{ Id = 'windows.inking-typing-data'; State = 'Disabled' }
    @{ Id = 'windows.defender-tools-exclusion'; State = 'Present' }
    @{ Id = 'windows.defender-bootstrap-exclusion'; State = 'Present' }
    @{ Id = 'windows.proxy-autoconfig-url'; State = 'Disabled' }
    @{ Id = 'windows.llmnr-policy'; State = 'Disabled' }
    @{ Id = 'windows.ssdp-discovery-service'; State = 'Disabled' }
    @{ Id = 'windows.upnp-device-host-service'; State = 'Disabled' }
    @{ Id = 'windows.winhttp-wpad-policy'; State = 'Disabled' }
    @{ Id = 'windows.background-apps-policy'; State = 'Disabled' }
    @{ Id = 'windows.admin-share-workstation'; State = 'Disabled' }
    @{ Id = 'windows.account-protection-warning'; State = 'Hidden' }
    @{ Id = 'windows.script-host-policy'; State = 'Disabled' }
    @{ Id = 'windows.dotnet-strong-crypto-64bit'; State = 'Enabled' }
    @{ Id = 'windows.dotnet-strong-crypto-32bit'; State = 'Enabled' }
    @{ Id = 'windows.f8-boot-menu-policy'; State = 'Legacy' }
    @{ Id = 'windows.dep-boot-policy'; State = 'OptOut' }
    @{ Id = 'windows.bitlocker-encryption-method'; State = 'AesCbc256' }
    @{ Id = 'windows.current-network-category'; State = 'Private' }
    @{ Id = 'windows.remote-assistance-policy'; State = 'Disabled' }
    @{ Id = 'windows.microsoft-product-updates'; State = 'Enabled' }
    @{ Id = 'windows.tailored-experiences-policy'; State = 'Disabled' }
    @{ Id = 'windows.activity-history-feed-policy'; State = 'Disabled' }
    @{ Id = 'windows.activity-history-publish-policy'; State = 'Disabled' }
    @{ Id = 'windows.activity-history-upload-policy'; State = 'Disabled' }
    @{ Id = 'windows.location-service-policy'; State = 'Disabled' }
    @{ Id = 'windows.location-scripting-policy'; State = 'Disabled' }
    @{ Id = 'windows.advertising-id-policy'; State = 'Disabled' }
    @{ Id = 'windows.website-language-list-policy'; State = 'Disabled' }
    @{ Id = 'windows.maintenance-wake-policy'; State = 'Disabled' }
    @{ Id = 'windows.maintenance-wake-timer'; State = 'Disabled' }
    @{ Id = 'windows.shared-experiences-policy'; State = 'Disabled' }
    @{ Id = 'windows.long-paths-policy'; State = 'Enabled' }
    @{ Id = 'windows.action-center-policy'; State = 'Disabled' }
    @{ Id = 'windows.toast-notifications-policy'; State = 'Disabled' }
    @{ Id = 'windows.lock-screen-blur'; State = 'Disabled' }
    @{ Id = 'windows.sticky-keys-prompts'; State = 'Disabled' }
    @{ Id = 'windows.toggle-keys-prompts'; State = 'Disabled' }
    @{ Id = 'windows.filter-keys-prompts'; State = 'Disabled' }
    @{ Id = 'windows.file-operation-details'; State = 'Enabled' }
    @{ Id = 'windows.taskbar-search-visibility'; State = 'Hidden' }
    @{ Id = 'windows.task-view-button'; State = 'Hidden' }
    @{ Id = 'windows.taskbar-combine-primary'; State = 'WhenFull' }
    @{ Id = 'windows.taskbar-combine-secondary'; State = 'WhenFull' }
    @{ Id = 'windows.taskbar-people-icon'; State = 'Hidden' }
    @{ Id = 'windows.tray-icon-promotion'; State = 'ShowAll' }
    @{ Id = 'windows.store-app-suggestion'; State = 'Disabled' }
    @{ Id = 'windows.new-app-alert'; State = 'Disabled' }
    @{ Id = 'windows.startup-sound'; State = 'Disabled' }
    @{ Id = 'windows.taskbar-widgets'; State = 'Hidden' }
    @{ Id = 'windows.taskbar-chat'; State = 'Hidden' }
    @{ Id = 'windows.edge-tabs-alt-tab'; State = 'Excluded' }
    @{ Id = 'windows.hidden-files-visibility'; State = 'Visible' }
    @{ Id = 'windows.navigation-pane-auto-expand'; State = 'Enabled' }
    @{ Id = 'windows.sync-provider-notifications'; State = 'Hidden' }
    @{ Id = 'windows.explorer-recent-shortcuts'; State = 'Hidden' }
    @{ Id = 'windows.explorer-frequent-shortcuts'; State = 'Hidden' }
    @{ Id = 'windows.explorer-start-location'; State = 'ThisPC' }
    @{ Id = 'windows.music-folder-this-pc'; State = 'Hidden' }
    @{ Id = 'windows.videos-folder-this-pc'; State = 'Hidden' }
    @{ Id = 'windows.3d-objects-folder-this-pc'; State = 'Hidden' }
    @{ Id = 'windows.thumbnail-cache-creation'; State = 'Disabled' }
    @{ Id = 'windows.network-thumbnail-database'; State = 'Disabled' }
    @{ Id = 'package.7zip'; State = 'Present' }
    @{ Id = 'package.git-for-windows'; State = 'Present' }
    @{ Id = 'package.sysmon64'; State = 'Present' }
  )
}
