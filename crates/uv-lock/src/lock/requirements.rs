use std::path::Path;

use uv_configuration::{
    NormalizedBuildConstraints, NormalizedConstraints, NormalizedOverrideEntries,
    NormalizedRequirements, Override, PackageOverride,
};
use uv_distribution_types::{
    IndexMetadata, IndexUrl, NameRequirementSpecification, Requirement, RequirementScope,
    RequirementSource, RequiresPython,
};
use uv_fs::normalize_path;
use uv_git_types::GitUrl;
use uv_pep508::VerbatimUrl;
use uv_pypi_types::{ParsedArchiveUrl, ParsedGitDirectoryUrl, ParsedGitPathUrl};
use uv_redacted::DisplaySafeUrl;

use super::{LockError, LockErrorKind};

/// Prepare dependency inputs for comparison with a lockfile's paths and supported Python versions.
///
/// Source and marker normalization precede collection normalization on both the stored declarations
/// and the current inputs. This also permits semantic comparison with older, unnormalized locks.
pub(super) struct RequirementNormalizer<'a> {
    root: &'a Path,
    requires_python: &'a RequiresPython,
}

impl<'a> RequirementNormalizer<'a> {
    pub(super) fn new(root: &'a Path, requires_python: &'a RequiresPython) -> Self {
        Self {
            root,
            requires_python,
        }
    }

    pub(super) fn requirements(
        &self,
        requirements: impl IntoIterator<Item = Requirement>,
    ) -> Result<NormalizedRequirements, LockError> {
        self.declarations(requirements)
            .map(NormalizedRequirements::from)
    }

    pub(super) fn constraints(
        &self,
        constraints: impl IntoIterator<Item = Requirement>,
    ) -> Result<NormalizedConstraints, LockError> {
        self.declarations(constraints)
            .map(NormalizedConstraints::from)
    }

    pub(super) fn overrides(
        &self,
        overrides: impl IntoIterator<Item = Override<Requirement>>,
    ) -> Result<NormalizedOverrideEntries, LockError> {
        overrides
            .into_iter()
            .map(|entry| match entry {
                Override::Requirement(requirement) => Ok(Override::Requirement(
                    normalize_requirement(requirement, self.root, self.requires_python)?,
                )),
                Override::Package(package) => Ok(Override::Package(PackageOverride {
                    package: package.package,
                    dependencies: self.declarations(package.dependencies)?.into_boxed_slice(),
                })),
            })
            .collect::<Result<Vec<_>, LockError>>()
            .map(NormalizedOverrideEntries::from)
    }

    pub(super) fn build_constraints(
        &self,
        constraints: impl IntoIterator<Item = NameRequirementSpecification>,
    ) -> Result<NormalizedBuildConstraints, LockError> {
        constraints
            .into_iter()
            .map(|constraint| {
                Ok(NameRequirementSpecification {
                    requirement: normalize_requirement(
                        constraint.requirement,
                        self.root,
                        self.requires_python,
                    )?,
                    hashes: constraint.hashes,
                })
            })
            .collect::<Result<Vec<_>, LockError>>()
            .map(NormalizedBuildConstraints::from)
    }

    fn declarations(
        &self,
        requirements: impl IntoIterator<Item = Requirement>,
    ) -> Result<Vec<Requirement>, LockError> {
        requirements
            .into_iter()
            .map(|requirement| normalize_requirement(requirement, self.root, self.requires_python))
            .collect()
    }
}

/// Normalize a [`Requirement`], which could come from a lockfile, a `pyproject.toml`, etc.
///
/// Performs the following steps:
///
/// 1. Removes any sensitive credentials.
/// 2. Ensures that the lock and install paths are appropriately framed with respect to the
///    workspace root.
/// 3. Removes the `origin` field, which is only used in `requirements.txt`.
/// 4. Simplifies the markers using the provided [`RequiresPython`] instance.
pub(super) fn normalize_requirement(
    mut requirement: Requirement,
    root: &Path,
    requires_python: &RequiresPython,
) -> Result<Requirement, LockError> {
    // Sort the extras and groups for consistency.
    requirement.extras.sort();
    requirement.groups.sort();

    // Normalize the requirement source.
    match requirement.source {
        RequirementSource::GitDirectory {
            git,
            subdirectory,
            url: _,
        } => {
            // Reconstruct the Git URL.
            let git = {
                let mut repository = git.url().clone();

                // Remove the credentials.
                repository.remove_credentials();

                // Remove the fragment and query from the URL; they're already present in the source.
                repository.set_fragment(None);
                repository.set_query(None);

                GitUrl::from_fields(
                    repository,
                    git.reference().clone(),
                    git.precise(),
                    git.lfs(),
                )?
            };

            // Reconstruct the PEP 508 URL from the underlying data.
            let url = DisplaySafeUrl::from(ParsedGitDirectoryUrl {
                url: git.clone(),
                subdirectory: subdirectory.clone(),
            });

            Ok(Requirement {
                name: requirement.name,
                extras: requirement.extras,
                groups: requirement.groups,
                marker: requires_python.simplify_markers(requirement.marker),
                source: RequirementSource::GitDirectory {
                    git,
                    subdirectory,
                    url: VerbatimUrl::from_url(url),
                },
                scope: RequirementScope::Global,
                origin: None,
            })
        }
        RequirementSource::GitPath {
            git,
            install_path,
            ext,
            url: _,
        } => {
            // Reconstruct the Git URL.
            let git = {
                let mut repository = git.url().clone();

                // Remove the credentials.
                repository.remove_credentials();

                // Remove the fragment and query from the URL; they're already present in the source.
                repository.set_fragment(None);
                repository.set_query(None);

                GitUrl::from_fields(
                    repository,
                    git.reference().clone(),
                    git.precise(),
                    git.lfs(),
                )?
            };

            // Reconstruct the PEP 508 URL from the underlying data.
            let url = DisplaySafeUrl::from(ParsedGitPathUrl {
                url: git.clone(),
                install_path: install_path.clone(),
                ext,
            });

            Ok(Requirement {
                name: requirement.name,
                extras: requirement.extras,
                groups: requirement.groups,
                marker: requires_python.simplify_markers(requirement.marker),
                source: RequirementSource::GitPath {
                    git,
                    install_path,
                    ext,
                    url: VerbatimUrl::from_url(url),
                },
                scope: RequirementScope::Global,
                origin: None,
            })
        }
        RequirementSource::Path {
            install_path,
            ext,
            url: _,
        } => {
            let path = root.join(&install_path);
            let install_path = normalize_path(path).into_owned().into_boxed_path();
            let url = VerbatimUrl::from_normalized_path(&install_path)
                .map_err(LockErrorKind::RequirementVerbatimUrl)?;

            Ok(Requirement {
                name: requirement.name,
                extras: requirement.extras,
                groups: requirement.groups,
                marker: requires_python.simplify_markers(requirement.marker),
                source: RequirementSource::Path {
                    install_path,
                    ext,
                    url,
                },
                scope: RequirementScope::Global,
                origin: None,
            })
        }
        RequirementSource::Directory {
            install_path,
            editable,
            r#virtual,
            url: _,
        } => {
            let path = root.join(&install_path);
            let install_path = normalize_path(path).into_owned().into_boxed_path();
            let url = VerbatimUrl::from_normalized_path(&install_path)
                .map_err(LockErrorKind::RequirementVerbatimUrl)?;

            Ok(Requirement {
                name: requirement.name,
                extras: requirement.extras,
                groups: requirement.groups,
                marker: requires_python.simplify_markers(requirement.marker),
                source: RequirementSource::Directory {
                    install_path,
                    editable: Some(editable.unwrap_or(false)),
                    r#virtual: Some(r#virtual.unwrap_or(false)),
                    url,
                },
                scope: RequirementScope::Global,
                origin: None,
            })
        }
        RequirementSource::Registry {
            specifier,
            index,
            conflict,
        } => {
            // Round-trip the index to remove anything apart from the URL.
            let index = index
                .map(|index| index.url.into_url())
                .map(|mut index| {
                    index.remove_credentials();
                    index
                })
                .map(|index| IndexMetadata::from(IndexUrl::from(VerbatimUrl::from_url(index))));
            Ok(Requirement {
                name: requirement.name,
                extras: requirement.extras,
                groups: requirement.groups,
                marker: requires_python.simplify_markers(requirement.marker),
                source: RequirementSource::Registry {
                    specifier,
                    index,
                    conflict,
                },
                scope: RequirementScope::Global,
                origin: None,
            })
        }
        RequirementSource::Url {
            mut location,
            subdirectory,
            ext,
            url: _,
        } => {
            // Remove the credentials.
            location.remove_credentials();

            // Remove the fragment from the URL; it's already present in the source.
            location.set_fragment(None);

            // Reconstruct the PEP 508 URL from the underlying data.
            let url = DisplaySafeUrl::from(ParsedArchiveUrl {
                url: location.clone(),
                subdirectory: subdirectory.clone(),
                ext,
            });

            Ok(Requirement {
                name: requirement.name,
                extras: requirement.extras,
                groups: requirement.groups,
                marker: requires_python.simplify_markers(requirement.marker),
                source: RequirementSource::Url {
                    location,
                    subdirectory,
                    ext,
                    url: VerbatimUrl::from_url(url),
                },
                scope: RequirementScope::Global,
                origin: None,
            })
        }
    }
}
