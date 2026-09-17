<#
Governed exception window: deletes one exceptional workload image from a
workload-image registry of the dependency authority.

This script is the placeholder-driven boilerplate of the only human
deletion path for a workload image: the governed exception window of the
operator access-class convention (the workload image lifecycle and
retention convention, owned by the cloud-agnostic dependency authority
reference, workload image lifecycle and retention section). Every project
that produces workload images carries this boilerplate on its operations
documentation surface, so the proven window form is adapted, never
reinvented.

The window form is the proven mutation-window form:
- the grant set is derived from the complete proven permission surface of
  the operation, never from its primary verb alone;
- the role content is proven against the provider's permission authority
  before the window, never assumed from the role name;
- every grant is proven by an independent read-back, and the dependent
  operation runs only after the propagation window and a simpler
  functional permission proof;
- the deletion is proven by the re-run inventory, never by the delete
  call's exit code — a permission denial while waiting on an already
  issued operation can still mean the deletion completed server-side, so
  the re-run inventory is the only arbiter of what is actually gone;
- the window ends in the proven hardened end state — no standing binding
  of the window role for the operator member, proven by read-back — and
  the hardening runs in the finally path, so a failed window never
  strands the grant.

Proven ordering facts of the deletion surface:
- a tagged digest refuses a plain delete; the bound form for an
  exceptional image is the complete delete with --delete-tags, which
  deletes the digest and all of its tags together;
- the platform refuses to delete a child manifest while a parent index
  still references it; when the exceptional content is an index-carried
  image set, delete the tagged index first, then the untagged child
  manifests — never the reverse order.

A live-bound image is untouchable: the script proves against the
organization instance's workload job bindings that no bound job image
references the target digest, and fails closed otherwise.

Bind every variable in the binding block before the run. The bound form
is never committed: every zone, project, registry, identity and digest is
a variable at the head of this boilerplate.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------ binding block (adapt) --------------------------
# Every value below is a placeholder. Bind the concrete organization
# values for the current window and never commit the bound form.
$OperatorMember = 'user:<EMAIL>'                  # the operator identity receiving the time-boxed window grant
$ControlProjectId = '<PROJECT_ID>'                # the control-zone project carrying the workload-image registries
$Region = '<REGION>'                              # the registry region
$RepositoryName = '<REPOSITORY_NAME>'             # staging-controller-images or release-controller-images
$ImageName = '<IMAGE_NAME>'                       # the image (package) name
$Digest = '<DIGEST>'                              # the sha256 hex digest of the exceptional image
$InstanceCheckoutPath = '<PATH>'                  # local checkout of the organization instance repository (the live-bound guard)
$WindowRole = 'roles/artifactregistry.admin'      # the proven minimal carrier of the complete window permission surface
$PropagationSeconds = 90                          # the IAM propagation window after every IAM change
# -------------------------------------------------------------------------

$ImageReference = "$Region-docker.pkg.dev/$ControlProjectId/$RepositoryName/$ImageName@sha256:$Digest"
$RepositoryReference = "$Region-docker.pkg.dev/$ControlProjectId/$RepositoryName"
$script:GrantActive = $false

function Assert-GcloudSuccess {
    param([string]$Step)
    if ($LASTEXITCODE -ne 0) {
        throw "gcloud step failed ($Step) with exit code $LASTEXITCODE"
    }
}

function Get-ActiveAccount {
    $account = (gcloud auth list --filter=status:ACTIVE --format="value(account)") | Out-String
    Assert-GcloudSuccess 'auth list'
    return $account.Trim()
}

function Assert-WindowRoleContent {
    # The role content is proven against the provider's permission
    # authority before the window — never assumed from the role name.
    $permissions = (gcloud iam roles describe $WindowRole --format="value(includedPermissions)") | Out-String
    Assert-GcloudSuccess 'iam roles describe'
    foreach ($required in @('artifactregistry.versions.delete', 'artifactregistry.dockerimages.list')) {
        if (-not $permissions.Contains($required)) {
            throw "the window role $WindowRole does not carry $required; the grant set must cover the complete proven permission surface"
        }
    }
}

function Assert-RegistryClass {
    # The exception window exists only for the workload-image registry
    # classes; the dependency repositories and the evidence plane are
    # append-only supply-chain records and never carry a human delete path.
    if ($RepositoryName -ne 'staging-controller-images' -and $RepositoryName -ne 'release-controller-images') {
        throw "$RepositoryName is not a workload-image registry class (staging-controller-images or release-controller-images)"
    }
}

function Assert-NotLiveBound {
    # A live-bound image is untouchable: the organization instance binds
    # every job image, and a bound digest is never deleted through the
    # exception window.
    $jobsPath = Join-Path $InstanceCheckoutPath (Join-Path 'registry' 'workload-jobs.yaml')
    if (-not (Test-Path $jobsPath)) {
        throw "the organization instance workload job bindings are not readable at $jobsPath; the live-bound guard fails closed"
    }
    $bindings = Get-Content -Raw $jobsPath
    if ($bindings.Contains($Digest)) {
        throw "the digest $Digest is referenced by the organization instance workload job bindings; a live-bound image is untouchable"
    }
}

function Get-OperatorProjectRoles {
    $policy = (gcloud projects get-iam-policy $ControlProjectId --format=json) | Out-String
    Assert-GcloudSuccess 'projects get-iam-policy'
    $parsed = $policy | ConvertFrom-Json
    $roles = @()
    if ($null -ne $parsed.bindings) {
        foreach ($binding in $parsed.bindings) {
            if ($binding.members -and ($binding.members -contains $OperatorMember)) {
                $roles += $binding.role
            }
        }
    }
    return $roles
}

function Get-ImageInventory {
    $inventory = (gcloud artifacts docker images list $RepositoryReference --project=$ControlProjectId) | Out-String
    Assert-GcloudSuccess 'artifacts docker images list'
    return $inventory
}

function Test-DigestPresent {
    param([string]$Inventory)
    return $Inventory.Contains("sha256:$Digest") -or $Inventory.Contains($Digest)
}

function Grant-WindowRole {
    gcloud projects add-iam-policy-binding $ControlProjectId --member="$OperatorMember" --role="$WindowRole" --format=none | Out-Null
    Assert-GcloudSuccess 'projects add-iam-policy-binding'
    $roles = Get-OperatorProjectRoles
    if (-not ($roles -contains $WindowRole)) {
        throw "the window role grant is not visible in the read-back policy; the grant is not proven"
    }
    $script:GrantActive = $true
}

function Remove-WindowRole {
    gcloud projects remove-iam-policy-binding $ControlProjectId --member="$OperatorMember" --role="$WindowRole" --format=none | Out-Null
    Assert-GcloudSuccess 'projects remove-iam-policy-binding'
    $roles = Get-OperatorProjectRoles
    if ($roles -contains $WindowRole) {
        throw "the window role is still present in the read-back policy; the hardened end state is not proven"
    }
    $script:GrantActive = $false
}

# ----------------------------- window phases -----------------------------
try {
    # Phase 0: preflights — fail closed before any mutation.
    $activeAccount = Get-ActiveAccount
    $expectedAccount = $OperatorMember -replace '^user:', ''
    if ($activeAccount -ne $expectedAccount) {
        throw "the active gcloud account '$activeAccount' is not the bound operator identity '$expectedAccount'; re-authenticate interactively (gcloud auth login), never through a scripted prompt"
    }
    Assert-RegistryClass
    Assert-WindowRoleContent
    Assert-NotLiveBound

    $rolesBefore = Get-OperatorProjectRoles
    if ($rolesBefore -contains $WindowRole) {
        throw "the operator already holds the window role on $ControlProjectId; the window starts from a hardened state"
    }

    $inventoryBefore = Get-ImageInventory
    if (-not (Test-DigestPresent $inventoryBefore)) {
        throw "the digest $Digest is not present in $RepositoryReference; there is nothing to delete"
    }

    # Phase 1: the grant, proven by the independent read-back.
    Grant-WindowRole

    # Phase 2: the propagation window, then the functional pre-verification
    # with a simpler permission proof (the inventory read under the grant).
    Start-Sleep -Seconds $PropagationSeconds
    $null = Get-ImageInventory

    # Phase 3: the deletion. The bound form for an exceptional image is the
    # complete delete with --delete-tags; the wait result of the delete call
    # is never the arbiter — the re-run inventory is.
    gcloud artifacts docker images delete $ImageReference --project=$ControlProjectId --delete-tags --quiet | Out-Null

    # Phase 4: the inventory read-back proof — the only arbiter of what is
    # actually gone.
    $inventoryAfter = Get-ImageInventory
    if (Test-DigestPresent $inventoryAfter) {
        throw "the digest $Digest is still present in $RepositoryReference after the delete call; the deletion is not proven"
    }

    Write-Output "exception window executed: $ImageReference is proven absent from $RepositoryReference"
}
finally {
    # Phase 5: the hardening — a failed window never strands the grant.
    if ($script:GrantActive) {
        Remove-WindowRole
        Write-Output 'hardening proven: the window role is removed and the read-back shows no standing binding'
    }
}
