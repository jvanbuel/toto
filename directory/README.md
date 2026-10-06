# The project directory

`projects.json` is the signed list of projects a contributor can add by name:

```
toto directory list
toto projects add acme-docs
```

It is a DSSE envelope over `projects.unsigned.json`, signed with the maintainers' key whose
public half is `maintainers.pub` (built into `toto`, overridable as `directory.public_key` in a
contributor's config). Runners verify the signature before trusting anything in it. Each entry
carries the project's id, repository, description, task kinds, harness, whether its agent needs
a network, and the project's public key as the repository published it when the entry was made:
`toto projects add` refuses a project whose repository now publishes a different key, so the
directory is the independent channel for the fingerprint.

## Listing a project (maintainers)

```
toto directory add owner/name --file directory/projects.unsigned.json   # reads the project's own files
toto directory sign --key <maintainers key> --file directory/projects.unsigned.json
git add directory && git commit -m "Directory: add owner/name"
```

`add` refreshes an entry whose id already exists (a project that rotated its key is re-listed
this way, deliberately). `remove` drops one. The maintainers' private key never enters the
repository; `toto project-key <file>` prints the public key of an existing key file.

Curation (ADR 7): list projects whose code and prompts you have looked at, since contributors
read this list as "someone checked". The entry is not a review of the image or the agent;
contributors still see and approve both when they add the project.
