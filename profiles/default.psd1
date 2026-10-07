@{
  SchemaVersion = 1
  Name = 'Default workstation'
  Description = 'A small starter configuration for a new Windows workstation.'
  Operations = @(
    @{ Id = 'windows.show-known-extensions'; State = 'Enabled' }
    @{ Id = 'windows.autoplay-policy'; State = 'Disabled' }
    @{ Id = 'windows.autorun-policy'; State = 'Disabled' }
    @{ Id = 'windows.inking-typing-data'; State = 'Disabled' }
    @{ Id = 'windows.defender-tools-exclusion'; State = 'Present' }
    @{ Id = 'windows.defender-bootstrap-exclusion'; State = 'Present' }
    @{ Id = 'windows.proxy-autoconfig-url'; State = 'Disabled' }
    @{ Id = 'windows.llmnr-policy'; State = 'Disabled' }
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
    @{ Id = 'windows.thumbnail-cache-creation'; State = 'Disabled' }
    @{ Id = 'windows.network-thumbnail-database'; State = 'Disabled' }
    @{ Id = 'package.7zip'; State = 'Present' }
  )
}
