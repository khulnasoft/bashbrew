package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"

	"github.com/docker-library/bashbrew/manifest"
	"github.com/urfave/cli"
)

type dockerfileStage struct {
	From      string // image name (or parent stage's image name, if "FROM stage-name")
	FromStage string // original stage name, if "FROM stage-name"
	Name      string // empty for unnamed stages
	Platform  string // empty string, $BUILDPLATFORM, or $TARGETPLATFORM
	// TODO somehow, we need to expose the platform of each stage to meta-scripts so it can know that, for example, the build stage base image is only needed for the *host* platform, not the target platform
}

type dockerfileMetadata struct {
	Stages      []dockerfileStage
	NamedStages map[string]int // map of stage names to index in Stages slice

	Froms []string // every "FROM" or "COPY --from=xxx" value (minus named and/or numbered stages in the case of "--from=")
}

// this returns the "FROM" value for the last stage (which essentially determines the "base" for the final published image)
func (r Repo) ArchLastStageFrom(arch string, entry *manifest.Manifest2822Entry) (string, error) {
	dockerfileMeta, err := r.archDockerfileMetadata(arch, entry)
	if err != nil {
		return "", err
	}
	return dockerfileMeta.Stages[len(dockerfileMeta.Stages)-1].From, nil
}

func (r Repo) DockerFroms(entry *manifest.Manifest2822Entry) ([]string, error) {
	return r.ArchDockerFroms(arch, entry)
}

func (r Repo) ArchDockerFroms(arch string, entry *manifest.Manifest2822Entry) ([]string, error) {
	dockerfileMeta, err := r.archDockerfileMetadata(arch, entry)
	if err != nil {
		return nil, err
	}
	return dockerfileMeta.Froms, nil
}

func (r Repo) dockerfileMetadata(entry *manifest.Manifest2822Entry) (*dockerfileMetadata, error) {
	return r.archDockerfileMetadata(arch, entry)
}

var dockerfileMetadataCache = map[string]*dockerfileMetadata{}

func (r Repo) archDockerfileMetadata(arch string, entry *manifest.Manifest2822Entry) (*dockerfileMetadata, error) {
	if builder := entry.ArchBuilder(arch); builder == "oci-import" {
		return &dockerfileMetadata{
			Stages: []dockerfileStage{{From: "scratch"}},
			Froms:  []string{"scratch"},
		}, nil
	}

	commit, err := r.fetchGitRepo(arch, entry)
	if err != nil {
		return nil, cli.NewMultiError(fmt.Errorf("failed fetching Git repo for arch %q from entry %q", arch, entry.String()), err)
	}

	dockerfileFile := path.Join(entry.ArchDirectory(arch), entry.ArchFile(arch))

	cacheKey := strings.Join([]string{
		commit,
		dockerfileFile,
	}, "\n")
	if meta, ok := dockerfileMetadataCache[cacheKey]; ok {
		return meta, nil
	}

	dockerfile, err := gitShow(commit, dockerfileFile)
	if err != nil {
		return nil, cli.NewMultiError(fmt.Errorf(`failed "git show" for %q from commit %q`, dockerfileFile, commit), err)
	}

	meta, err := parseDockerfileMetadata(dockerfile)
	if err != nil {
		return nil, cli.NewMultiError(fmt.Errorf(`failed parsing Dockerfile metadata for %q from commit %q`, dockerfileFile, commit), err)
	}

	dockerfileMetadataCache[cacheKey] = meta
	return meta, nil
}

func parseDockerfileMetadata(dockerfile string) (*dockerfileMetadata, error) {
	meta := &dockerfileMetadata{
		// panic: assignment to entry in nil map
		NamedStages: map[string]int{},
		// (nil slices work fine)
	}

	scanner := bufio.NewScanner(strings.NewReader(dockerfile))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			// ignore blank lines
			continue
		}

		if line[0] == '#' {
			// TODO handle "escape" parser directive
			// TODO handle "syntax" parser directive -- explode appropriately (since custom syntax invalidates our Dockerfile parsing)
			// ignore comments
			continue
		}

		// handle line continuations
		// (TODO see note above regarding "escape" parser directive)
		for line[len(line)-1] == '\\' && scanner.Scan() {
			nextLine := strings.TrimSpace(scanner.Text())
			if nextLine == "" || nextLine[0] == '#' {
				// ignore blank lines and comments
				continue
			}
			line = line[0:len(line)-1] + nextLine
		}

		fields := strings.Fields(line)
		if len(fields) < 1 {
			// must be a much more complex empty line??
			continue
		}
		instruction := strings.ToUpper(fields[0])
		args := fields[1:]

		switch instruction {
		case "FROM":
			var stage dockerfileStage
			if platform, ok := strings.CutPrefix(args[0], "--platform="); ok {
				stage.Platform = platform
				args = args[1:]
				switch stage.Platform {
				case "$BUILDPLATFORM", "$TARGETPLATFORM":
					// explicitly allowed for more efficient cross-compiling (see also condition outside the meta loop to ensure the final stage is either without platform or explicitly --platform=$TARGETPLATFORM)
				default:
					return nil, fmt.Errorf("FROM has unsupported --platform=%q -- any --platform must be generic or unspecified for correct dependency calculation", stage.Platform)
				}
			}

			stage.From = args[0]
			args = args[1:]

			if strings.ContainsRune(stage.From, '$') {
				return nil, fmt.Errorf("FROM %q contains invalid/disallowed character '$' -- explicit FROM values are required for dependency calculation", stage.From)
			}

			if i, ok := meta.NamedStages[stage.From]; ok {
				// if this is a valid stage name, we should resolve it back to the original FROM value of that previous stage (we don't care about inter-stage dependencies for the purposes of either tag dependency calculation or tag building -- just how many there are and what external things they require)
				parent := meta.Stages[i]
				if stage.Platform == "" {
					stage.Platform = parent.Platform
				} else if stage.Platform != parent.Platform {
					return nil, fmt.Errorf("FROM %q has --platform=%q but stage %q has --platform=%q", stage.From, stage.Platform, stage.From, parent.Platform)
				}
				stage.FromStage = stage.From
				stage.From = parent.From
			} else {
				// make sure to add ":latest" if it's implied
				stage.From = latestizeRepoTag(stage.From)
			}

			i := len(meta.Stages)
			if len(args) == 2 && strings.ToUpper(args[0]) == "AS" {
				stage.Name = args[1]
				meta.NamedStages[stage.Name] = i
			}
			meta.Stages = append(meta.Stages, stage)

			meta.Froms = append(meta.Froms, stage.From)

		// TODO somehow include "RUN --mount=type=bind,from=IMAGE,foo=bar" (without too much insanity)
		case "COPY":
			for _, arg := range args {
				if !strings.HasPrefix(arg, "--") {
					// doesn't appear to be a "flag"; time to bail!
					break
				}
				from, ok := strings.CutPrefix(arg, "--from=")
				if !ok {
					// ignore any flags we're not interested in
					continue
				}

				if i, ok := meta.NamedStages[from]; ok {
					// see note above regarding stage names in FROM
					from = meta.Stages[i].From
				} else if stageNumber, err := strconv.Atoi(from); err == nil && stageNumber < len(meta.Stages) {
					// must be a stage number, we should resolve it too
					from = meta.Stages[stageNumber].From
				} else {
					// make sure to add ":latest" if it's implied
					from = latestizeRepoTag(from)
				}

				meta.Froms = append(meta.Froms, from)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	finalStage := meta.Stages[len(meta.Stages)-1]
	switch finalStage.Platform {
	case "", "$TARGETPLATFORM":
		// yay, all is well
	default:
		return nil, fmt.Errorf("final stage/FROM (%q) has --platform=%q but must be unspecified or $TARGETPLATFORM", finalStage.From, finalStage.Platform)
	}

	return meta, nil
}

func (r Repo) DockerCacheName(entry *manifest.Manifest2822Entry) (string, error) {
	cacheHash, err := r.dockerCacheHash(entry)
	if err != nil {
		return "", err
	}
	return "bashbrew/cache:" + cacheHash, err
}

func (r Repo) dockerCacheHash(entry *manifest.Manifest2822Entry) (string, error) {
	uniqueBits, err := r.dockerBuildUniqueBits(entry)
	if err != nil {
		return "", err
	}
	uniqueString := strings.Join(uniqueBits, "\n")
	b := sha256.Sum256([]byte(uniqueString))
	return hex.EncodeToString(b[:]), nil
}

func dockerInspect(format string, args ...string) (string, error) {
	args = append([]string{"inspect", "-f", format}, args...)
	out, err := exec.Command("docker", args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("%v\ncommand: docker inspect -f %q %q\n%s", ee, format, args, string(ee.Stderr))
		}
	}
	return strings.TrimSpace(string(out)), nil
}

var dockerFromIdCache = map[string]string{
	"scratch": "scratch",
}

func (r Repo) dockerBuildUniqueBits(entry *manifest.Manifest2822Entry) ([]string, error) {
	uniqueBits := []string{
		entry.ArchGitRepo(arch),
		entry.ArchGitCommit(arch),
		entry.ArchDirectory(arch),
		entry.ArchFile(arch),
	}
	if builder := entry.ArchBuilder(arch); builder != "" {
		// NOTE: preserve long-term unique id by only attaching builder if
		// explicitly specified
		uniqueBits = append(uniqueBits, entry.ArchBuilder(arch))
	}
	meta, err := r.dockerfileMetadata(entry)
	if err != nil {
		return nil, err
	}
	for _, from := range meta.Froms {
		fromId, ok := dockerFromIdCache[from]
		if !ok {
			var err error
			fromId, err = dockerInspect("{{.Id}}", from)
			if err != nil {
				return nil, err
			}
			dockerFromIdCache[from] = fromId
		}
		uniqueBits = append(uniqueBits, fromId)
	}
	return uniqueBits, nil
}

func dockerBuild(tags []string, file string, context io.Reader, platform string) error {
	args := []string{"build"}
	for _, tag := range tags {
		args = append(args, "--tag", tag)
	}
	if file != "" {
		args = append(args, "--file", file)
	}
	args = append(args, "--rm", "--force-rm", "-")

	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), "DOCKER_BUILDKIT=0")
	if debugFlag {
		fmt.Println("$ export DOCKER_BUILDKIT=0")
	}
	if platform != "" {
		// ideally, we would set this via an explicit "--platform" flag on "docker build", but it's not supported without buildkit until 20.10+ and this is a trivial way to get Docker to do the right thing in both cases without explicitly trying to detect whether we're on 20.10+
		// https://github.com/docker/cli/blob/v20.10.7/cli/command/image/build.go#L163
		cmd.Env = append(cmd.Env, "DOCKER_DEFAULT_PLATFORM="+platform)
		if debugFlag {
			fmt.Printf("$ export DOCKER_DEFAULT_PLATFORM=%q\n", platform)
		}
	}
	cmd.Stdin = context
	if debugFlag {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		fmt.Printf("$ docker %q\n", args)
		return cmd.Run()
	} else {
		buf := &bytes.Buffer{}
		cmd.Stdout = buf
		cmd.Stderr = buf
		err := cmd.Run()
		if err != nil {
			err = cli.NewMultiError(err, fmt.Errorf(`docker %q output:%s`, args, "\n"+buf.String()))
		}
		return err
	}
}

const (
	dockerfileSyntaxEnv = "BASHBREW_BUILDKIT_SYNTAX"
	sbomGeneratorEnv    = "BASHBREW_BUILDKIT_SBOM_GENERATOR"
	buildxBuilderEnv    = "BUILDX_BUILDER"
)

func dockerBuildxBuild(tags []string, file string, context io.Reader, platform string) error {
	dockerfileSyntax, ok := os.LookupEnv(dockerfileSyntaxEnv)
	if !ok {
		return fmt.Errorf("missing %q", dockerfileSyntaxEnv)
	}

	args := []string{
		"buildx",
		"build",
		"--progress", "plain",
		"--build-arg", "BUILDKIT_SYNTAX=" + dockerfileSyntax,
	}
	buildxBuilder := "" != os.Getenv(buildxBuilderEnv)
	if buildxBuilder {
		args = append(args, "--provenance", "mode=max")
	}
	if sbomGenerator, ok := os.LookupEnv(sbomGeneratorEnv); ok {
		if buildxBuilder {
			args = append(args, "--sbom", "generator="+sbomGenerator)
		} else {
			return fmt.Errorf("have %q but missing %q", sbomGeneratorEnv, buildxBuilderEnv)
		}
	}
	if platform != "" {
		args = append(args, "--platform", platform)
	}
	for _, tag := range tags {
		args = append(args, "--tag", tag)
	}
	if file != "" {
		args = append(args, "--file", file)
	}
	args = append(args, "-")

	if buildxBuilder {
		args = append(args, "--output", "type=oci")
		// TODO ,annotation.xyz.khulnasoft.foo=bar,annotation-manifest-descriptor.xyz.khulnasoft.foo=bar (for OCI source annotations, which this function doesn't currently have access to)
	}

	cmd := exec.Command("docker", args...)
	cmd.Stdin = context

	run := func() error {
		return cmd.Run()
	}
	if buildxBuilder {
		run = func() error {
			pipe, err := cmd.StdoutPipe()
			if err != nil {
				return err
			}
			defer pipe.Close()

			err = cmd.Start()
			if err != nil {
				return err
			}
			defer cmd.Process.Kill()

			_, err = containerdImageLoad(pipe)
			if err != nil {
				return err
			}
			pipe.Close()

			err = cmd.Wait()
			if err != nil {
				return err
			}

			desc, err := containerdImageLookup(tags[0])
			if err != nil {
				return err
			}

			fmt.Printf("Importing %s into Docker\n", desc.Digest)
			err = containerdDockerLoad(*desc, tags)
			if err != nil {
				return err
			}

			return nil
		}
	}

	// intentionally not touching os.Stdout because "buildx build" does *not* put any build output to stdout and in some cases (see above) we use stdout to capture an OCI tarball and pipe it into containerd
	if debugFlag {
		cmd.Stderr = os.Stderr
		fmt.Printf("$ docker %q\n", args)
		return run()
	} else {
		buf := &bytes.Buffer{}
		cmd.Stderr = buf
		err := run()
		if err != nil {
			err = cli.NewMultiError(err, fmt.Errorf(`docker %q output:%s`, args, "\n"+buf.String()))
		}
		return err
	}
}

func dockerTag(tag1 string, tag2 string) error {
	if debugFlag {
		fmt.Printf("$ docker tag %q %q\n", tag1, tag2)
	}
	_, err := exec.Command("docker", "tag", tag1, tag2).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("%v\ncommand: docker tag %q %q\n%s", ee, tag1, tag2, string(ee.Stderr))
		}
	}
	return err
}

func dockerPush(tag string) error {
	if debugFlag {
		fmt.Printf("$ docker push %q\n", tag)
	}
	_, err := exec.Command("docker", "push", tag).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("%v\ncommand: docker push %q\n%s", ee, tag, string(ee.Stderr))
		}
	}
	return err
}

func dockerPull(tag string) error {
	if debugFlag {
		fmt.Printf("$ docker pull %q\n", tag)
	}
	_, err := exec.Command("docker", "pull", tag).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("%v\ncommand: docker pull %q\n%s", ee, tag, string(ee.Stderr))
		}
	}
	return err
}
