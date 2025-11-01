@{
    # Script module or binary module file associated with this manifest.
    RootModule        = 'LinuxUtils.psm1'

    # Version number of this module.
    ModuleVersion     = '1.0.0'

    # ID used to uniquely identify this module
    GUID              = 'd3f5a1c1-8b2a-4c9f-9a3b-1f2e3d4c5b6a'

    # Author of this module
    Author            = 'Ryan Zurrin'

    # Company or vendor of this module
    CompanyName       = 'Private'

    # Description of the functionality provided by this module
    Description       = 'A PowerShell module to emulate common GNU/Linux utilities in Windows (ls, wc, grep, touch, tree, cd stack, etc.)'

    # Minimum version of the PowerShell engine required
    PowerShellVersion = '5.1'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules   = @()

    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies = @()

    # Functions to export from this module
    FunctionsToExport = @(
        'Measure-LinuxUtil',
        'Get-DiskHealth',
        'wc',
        'ls',
        'touch',
        'grep',
        'head',
        'tail',
        'rm',
        'which',
        'df',
        'tree',
        'cd',
        'go',
        'dirs'
    )

    # Cmdlets to export from this module
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport   = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData       = @{}

    # Help info URI
    HelpInfoURI       = ''

}
