package com.shieldforge.app.core.common

import kotlinx.serialization.Serializable

@Serializable
data class ComponentProtectionOverride(
    val componentId: String,
    val componentType: ComponentType,
    val displayName: String,
    val inheritGlobal: Boolean = true,
    val enabledModules: Set<ProtectionModuleId> = emptySet(),
    val stripDebugInfo: Boolean = true,
    val encryptSensitiveStrings: Boolean = true,
    val excludeFromTransformation: Boolean = false,
)

@Serializable
data class SelectionStateSnapshot(
    val selectedDexFiles: Set<String> = emptySet(),
    val selectedPackages: Set<String> = emptySet(),
    val selectedClasses: Set<String> = emptySet(),
    val selectedMethods: Set<String> = emptySet(),
    val selectedFields: Set<String> = emptySet(),
    val selectedStrings: Set<String> = emptySet(),
    val selectedResources: Set<String> = emptySet(),
    val selectedManifestItems: Set<String> = emptySet(),
    val overrides: Map<String, ComponentProtectionOverride> = emptyMap(),
) {
    val totalSelectedCount: Int
        get() = selectedDexFiles.size +
            selectedPackages.size +
            selectedClasses.size +
            selectedMethods.size +
            selectedFields.size +
            selectedStrings.size +
            selectedResources.size +
            selectedManifestItems.size
}

@Serializable
data class SelectionProfileExport(
    val profileName: String,
    val packageName: String,
    val exportedAtMs: Long,
    val selection: SelectionStateSnapshot,
)

enum class ExplorerFilterMode(val label: String) {
    ALL("All"),
    SELECTED_ONLY("Selected"),
    TRANSFORMABLE_ONLY("Transformable"),
    SENSITIVE_ONLY("Sensitive"),
    CAUTION_ONLY("Caution / Restricted"),
}

enum class WorkspaceTab(val title: String, val shortTitle: String) {
    OVERVIEW("Overview", "Overview"),
    DEX_EXPLORER("DEX Explorer", "DEX"),
    PACKAGE_EXPLORER("Package Explorer", "Packages"),
    CLASS_EXPLORER("Class Explorer", "Classes"),
    METHOD_EXPLORER("Method Explorer", "Methods"),
    FIELD_EXPLORER("Field Explorer", "Fields"),
    STRING_EXPLORER("String Explorer", "Strings"),
    MANIFEST_EXPLORER("Manifest Explorer", "Manifest"),
    RESOURCE_EXPLORER("Resource Explorer", "Resources"),
    PROTECTION_CONFIG("Protection Configuration", "Config"),
    PROCESSING_LOGS("Processing Logs", "Logs"),
    FINAL_REPORT("Final Report", "Report"),
}
