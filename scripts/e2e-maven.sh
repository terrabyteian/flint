#!/usr/bin/env bash
# e2e-maven.sh drives flint's Maven repositories with real clients: Maven
# deploys a library with sources and javadoc to a hosted release
# repository and a snapshot twice to a hosted snapshot repository, and
# builds a project with real dependencies from Maven Central through a
# virtual repository, resolving the latest snapshot; each Gradle given
# publishes a library with Gradle module metadata and sha256 and sha512
# checksums, and a second project resolves it. The script also checks
# immutable releases, checksums, deletes, and dependency-confusion
# protection. A second run, after flint has been restarted with its
# upstream unreachable, builds the same projects again with empty local
# caches to prove that cached content keeps being served offline. It
# fails on the first mismatch.
#
# Usage: E2E_STATE_DIR=<dir> E2E_USER=<user:token> E2E_ADMIN=<user:password> \
#          E2E_GRADLE="<gradle> [<gradle>...]" \
#          scripts/e2e-maven.sh online|offline <host:port> <releases> <snapshots> <proxy> <virtual>
#   <releases>   a hosted Maven repository with the default version policy,
#                release
#   <snapshots>  a hosted Maven repository with versionPolicy snapshot
#   <proxy>      a proxy repository of Maven Central with anonymousPull
#   <virtual>    a virtual repository of <releases>, <snapshots>, and <proxy>,
#                in that order, with anonymousPull and dependency-confusion
#                protection, whose <proxy> member excludes com.flint.e2e.*
#   E2E_USER     a user name and API token with write on <releases> and
#                <snapshots>
#   E2E_ADMIN    credentials with the delete role on <releases>
#   E2E_GRADLE   Gradle executables, such as Gradle 8 and Gradle 9
#   E2E_STATE_DIR keeps what the online run built for the offline run.
# Requires java (17 or later), mvn, the Gradle executables, and curl.
set -euo pipefail

if [ $# -ne 6 ] || [ -z "${E2E_STATE_DIR:-}" ] || [ -z "${E2E_USER:-}" ] || [ -z "${E2E_ADMIN:-}" ] ||
	[ -z "${E2E_GRADLE:-}" ] || { [ "$1" != online ] && [ "$1" != offline ]; }; then
	echo "usage: E2E_STATE_DIR=<dir> E2E_USER=<user:token> E2E_ADMIN=<user:password> E2E_GRADLE=\"<gradle>...\" $0 online|offline <host:port> <releases> <snapshots> <proxy> <virtual>" >&2
	exit 2
fi
mode=$1
reg=$2
releases=$3
snapshots=$4
proxy=$5
virtual=$6
state=$E2E_STATE_DIR
mkdir -p "$state"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
step() { echo "--- $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}

base=http://$reg/maven
user=${E2E_USER%%:*}
token=${E2E_USER#*:}
read -r -a gradles <<<"$E2E_GRADLE"
group=com/flint/e2e

# status prints the HTTP status of a request.
status() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }

# metric prints the value of a flint metric sample, or 0.
metric() {
	curl -fsS "http://$reg/metrics" | awk -v s="$1" '$1 == s { print $2; found = 1 } END { if (!found) print 0 }'
}

# sha prints the hex digest of a file in algorithm $1 (1, 256, or 512).
sha() { shasum -a "$1" "$2" | cut -d' ' -f1; }

# settings writes a Maven settings file that sends every repository to
# the virtual repository, with snapshots enabled, and gives the deploy
# credentials.
settings() {
	cat >"$1" <<-XML
		<settings>
		  <mirrors>
		    <mirror><id>flint</id><mirrorOf>*</mirrorOf><url>$base/$virtual/</url></mirror>
		  </mirrors>
		  <profiles>
		    <profile>
		      <id>flint</id>
		      <repositories>
		        <repository><id>central</id><url>http://central</url><snapshots><enabled>true</enabled></snapshots></repository>
		      </repositories>
		      <pluginRepositories>
		        <pluginRepository><id>central</id><url>http://central</url><snapshots><enabled>true</enabled></snapshots></pluginRepository>
		      </pluginRepositories>
		    </profile>
		  </profiles>
		  <activeProfiles><activeProfile>flint</activeProfile></activeProfiles>
		  <servers>
		    <server><id>flint-releases</id><username>$user</username><password>$token</password></server>
		    <server><id>flint-snapshots</id><username>$user</username><password>$token</password></server>
		  </servers>
		</settings>
	XML
}

# mvnw runs Maven in project directory $1, with an empty local repository
# of its own, $2, and the remaining arguments.
mvnw() {
	local dir=$1 repo=$2
	shift 2
	(cd "$dir" && mvn -B -ntp -Dstyle.color=never -s "$work/settings.xml" -Dmaven.repo.local="$repo" "$@")
}

# library writes a Maven library project: artifact $2, version $3, whose
# class $4 has the constant VERSION = $5, depending on commons-lang3,
# with sources and javadoc, deploying to the hosted repositories.
library() {
	local dir=$1 artifact=$2 version=$3 class=$4 value=$5
	mkdir -p "$dir/src/main/java/com/flint/e2e"
	cat >"$dir/pom.xml" <<-XML
		<project xmlns="http://maven.apache.org/POM/4.0.0">
		  <modelVersion>4.0.0</modelVersion>
		  <groupId>com.flint.e2e</groupId>
		  <artifactId>$artifact</artifactId>
		  <version>$version</version>
		  <properties>
		    <maven.compiler.release>17</maven.compiler.release>
		    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
		  </properties>
		  <dependencies>
		    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.17.0</version></dependency>
		  </dependencies>
		  <build>
		    <plugins>
		      <plugin>
		        <artifactId>maven-source-plugin</artifactId><version>3.3.1</version>
		        <executions><execution><goals><goal>jar-no-fork</goal></goals></execution></executions>
		      </plugin>
		      <plugin>
		        <artifactId>maven-javadoc-plugin</artifactId><version>3.11.2</version>
		        <executions><execution><goals><goal>jar</goal></goals></execution></executions>
		      </plugin>
		    </plugins>
		  </build>
		  <distributionManagement>
		    <repository><id>flint-releases</id><url>$base/$releases/</url></repository>
		    <snapshotRepository><id>flint-snapshots</id><url>$base/$snapshots/</url></snapshotRepository>
		  </distributionManagement>
		</project>
	XML
	cat >"$dir/src/main/java/com/flint/e2e/$class.java" <<-JAVA
		package com.flint.e2e;

		/** A class of the end-to-end test library. */
		public final class $class {
		    /** The library's build. */
		    public static final String VERSION = "$value";

		    private $class() {}

		    /** Greets someone, capitalized. */
		    public static String greet(String name) {
		        return "hello " + org.apache.commons.lang3.StringUtils.capitalize(name);
		    }
		}
	JAVA
}

# app writes a Maven project that depends on the library, the snapshot,
# and real artifacts from Maven Central, and tests that it got the
# snapshot's latest build.
app() {
	local dir=$1
	mkdir -p "$dir/src/main/java/app" "$dir/src/test/java/app"
	cat >"$dir/pom.xml" <<-XML
		<project xmlns="http://maven.apache.org/POM/4.0.0">
		  <modelVersion>4.0.0</modelVersion>
		  <groupId>com.flint.e2e</groupId>
		  <artifactId>flint-e2e-app</artifactId>
		  <version>1.0.0</version>
		  <properties>
		    <maven.compiler.release>17</maven.compiler.release>
		    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
		  </properties>
		  <dependencies>
		    <dependency><groupId>com.flint.e2e</groupId><artifactId>flint-e2e-lib</artifactId><version>1.0.0</version></dependency>
		    <dependency><groupId>com.flint.e2e</groupId><artifactId>flint-e2e-snap</artifactId><version>1.1-SNAPSHOT</version></dependency>
		    <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>33.4.0-jre</version></dependency>
		    <dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId><version>5.11.4</version><scope>test</scope></dependency>
		  </dependencies>
		</project>
	XML
	cat >"$dir/src/main/java/app/App.java" <<-'JAVA'
		package app;

		public final class App {
		    public static String run() {
		        return com.google.common.base.Joiner.on(", ").join(com.flint.e2e.Lib.greet("flint"), com.flint.e2e.Snap.VERSION);
		    }
		}
	JAVA
	cat >"$dir/src/test/java/app/AppTest.java" <<-'JAVA'
		package app;

		import static org.junit.jupiter.api.Assertions.assertEquals;

		import org.junit.jupiter.api.Test;

		class AppTest {
		    @Test
		    void resolvesTheLatestSnapshot() {
		        assertEquals("hello Flint, build 2", App.run());
		    }
		}
	JAVA
}

# greeter writes a Gradle library, artifact flint-e2e-greeter at version
# $2, publishing to the hosted release repository with Gradle module
# metadata, and depending on the Maven library through the API.
greeter() {
	local dir=$1 version=$2
	mkdir -p "$dir/src/main/java/com/flint/e2e"
	echo "rootProject.name = 'flint-e2e-greeter'" >"$dir/settings.gradle"
	cat >"$dir/build.gradle" <<-GRADLE
		plugins {
		    id 'java-library'
		    id 'maven-publish'
		}
		group = 'com.flint.e2e'
		version = '$version'
		java { withSourcesJar() }
		repositories {
		    maven { url = '$base/$virtual/'; allowInsecureProtocol = true }
		}
		dependencies {
		    api 'com.flint.e2e:flint-e2e-lib:1.0.0'
		}
		publishing {
		    publications { lib(MavenPublication) { from components.java } }
		    repositories {
		        maven {
		            name = 'flint'
		            url = '$base/$releases/'
		            allowInsecureProtocol = true
		            credentials(PasswordCredentials)
		        }
		    }
		}
	GRADLE
	cat >"$dir/src/main/java/com/flint/e2e/Greeter.java" <<-'JAVA'
		package com.flint.e2e;

		public final class Greeter {
		    public static String greet() {
		        return Lib.greet("gradle");
		    }
		}
	JAVA
}

# consumer writes a Gradle project that compiles against the Gradle
# library at version $2, and through its API dependency the Maven one.
consumer() {
	local dir=$1 version=$2
	mkdir -p "$dir/src/main/java/app"
	cat >"$dir/settings.gradle" <<-GRADLE
		rootProject.name = 'flint-e2e-consumer'
		dependencyResolutionManagement {
		    repositories {
		        maven { url = '$base/$virtual/'; allowInsecureProtocol = true }
		    }
		}
	GRADLE
	cat >"$dir/build.gradle" <<-GRADLE
		plugins { id 'java' }
		dependencies {
		    implementation 'com.flint.e2e:flint-e2e-greeter:$version'
		}
	GRADLE
	cat >"$dir/src/main/java/app/Main.java" <<-'JAVA'
		package app;

		public final class Main {
		    public static String run() {
		        return com.flint.e2e.Greeter.greet() + " " + com.flint.e2e.Lib.VERSION;
		    }
		}
	JAVA
}

# gradlew runs Gradle $1 in project directory $2 with an empty Gradle
# home of its own, $3, and the remaining arguments.
gradlew() {
	local gradle=$1 dir=$2 home=$3
	shift 3
	(cd "$dir" && GRADLE_USER_HOME=$home ORG_GRADLE_PROJECT_flintUsername=$user ORG_GRADLE_PROJECT_flintPassword=$token \
		"$gradle" --no-daemon --console=plain -q "$@")
}

# major prints the major version of Gradle executable $1.
major() { "$1" --version | awk '/^Gradle / { split($2, v, "."); print v[1] }'; }

settings "$work/settings.xml"

if [ "$mode" = online ]; then
	step "mvn deploys a library with sources and javadoc to $releases"
	library "$work/lib" flint-e2e-lib 1.0.0 Lib "release"
	mvnw "$work/lib" "$work/m2-lib" deploy
	for f in flint-e2e-lib-1.0.0.jar flint-e2e-lib-1.0.0.pom flint-e2e-lib-1.0.0-sources.jar flint-e2e-lib-1.0.0-javadoc.jar; do
		curl -fsS -u "$E2E_USER" -o "$work/$f" "$base/$releases/$group/flint-e2e-lib/1.0.0/$f" || fail "$f was not deployed"
		[ "$(curl -fsS -u "$E2E_USER" "$base/$releases/$group/flint-e2e-lib/1.0.0/$f.sha1")" = "$(sha 1 "$work/$f")" ] ||
			fail "the .sha1 of $f does not match it"
	done
	cmp -s "$work/flint-e2e-lib-1.0.0.jar" "$work/lib/target/flint-e2e-lib-1.0.0.jar" || fail "the deployed jar differs from the built one"
	md=$(curl -fsS -u "$E2E_USER" "$base/$releases/$group/flint-e2e-lib/maven-metadata.xml")
	grep -q '<release>1.0.0</release>' <<<"$md" || fail "the metadata of flint-e2e-lib does not name release 1.0.0: $md"
	[ "$(status "$base/$releases/$group/flint-e2e-lib/maven-metadata.xml")" = 401 ] || fail "$releases answered an anonymous client"
	cp "$work/lib/target/flint-e2e-lib-1.0.0.jar" "$state/"

	step "a release never changes: redeploying different content fails with 409"
	sed -i.bak 's/hello /hi /' "$work/lib/src/main/java/com/flint/e2e/Lib.java"
	if out=$(mvnw "$work/lib" "$work/m2-lib" deploy 2>&1); then
		fail "redeploying release 1.0.0 with different content succeeded"
	fi
	grep -q 409 <<<"$out" || fail "redeploying a release failed without a 409: $out"
	[ "$(status -u "$E2E_USER" -T "$state/flint-e2e-lib-1.0.0.jar" "$base/$releases/$group/flint-e2e-lib/1.0.0/flint-e2e-lib-1.0.0.jar")" = 200 ] ||
		fail "re-uploading the same bytes did not succeed"
	cmp -s "$state/flint-e2e-lib-1.0.0.jar" <(curl -fsS -u "$E2E_USER" "$base/$releases/$group/flint-e2e-lib/1.0.0/flint-e2e-lib-1.0.0.jar") ||
		fail "the release changed"

	step "a snapshot is refused by $releases"
	[ "$(status -u "$E2E_USER" -T "$state/flint-e2e-lib-1.0.0.jar" \
		"$base/$releases/$group/flint-e2e-lib/1.1-SNAPSHOT/flint-e2e-lib-1.1-20261011.120000-1.jar")" = 400 ] ||
		fail "$releases accepted a snapshot"

	step "mvn deploys a snapshot to $snapshots twice"
	library "$work/snap" flint-e2e-snap 1.1-SNAPSHOT Snap "build 1"
	mvnw "$work/snap" "$work/m2-snap" deploy
	library "$work/snap" flint-e2e-snap 1.1-SNAPSHOT Snap "build 2"
	mvnw "$work/snap" "$work/m2-snap" deploy
	md=$(curl -fsS -u "$E2E_USER" "$base/$snapshots/$group/flint-e2e-snap/1.1-SNAPSHOT/maven-metadata.xml")
	grep -q '<buildNumber>2</buildNumber>' <<<"$md" || fail "the snapshot metadata does not name build 2: $md"

	step "mvn builds a project with real dependencies through $virtual, resolving the latest snapshot"
	app "$work/app"
	mvnw "$work/app" "$work/m2-app" package
	cp -r "$work/app" "$state/"
	[ -f "$work/m2-app/com/google/guava/guava/33.4.0-jre/guava-33.4.0-jre.jar" ] || fail "guava was not resolved"

	for gradle in "${gradles[@]}"; do
		v=$(major "$gradle")
		step "Gradle $v publishes with module metadata and sha256 and sha512 checksums"
		greeter "$work/greeter-$v" "2.0.$v"
		gradlew "$gradle" "$work/greeter-$v" "$work/gradle-home-$v" publish
		dir=$base/$releases/$group/flint-e2e-greeter/2.0.$v
		for f in "flint-e2e-greeter-2.0.$v.module" "flint-e2e-greeter-2.0.$v.jar" "flint-e2e-greeter-2.0.$v-sources.jar"; do
			curl -fsS -u "$E2E_USER" -o "$work/$f" "$dir/$f" || fail "Gradle $v did not publish $f"
			[ "$(curl -fsS -u "$E2E_USER" "$dir/$f.sha256")" = "$(sha 256 "$work/$f")" ] || fail "the .sha256 of $f does not match it"
			[ "$(curl -fsS -u "$E2E_USER" "$dir/$f.sha512")" = "$(sha 512 "$work/$f")" ] || fail "the .sha512 of $f does not match it"
		done
		grep -q '"formatVersion"' "$work/flint-e2e-greeter-2.0.$v.module" || fail "the .module file is not Gradle module metadata"

		step "Gradle $v resolves the published module from a second project through $virtual"
		consumer "$work/consumer-$v" "2.0.$v"
		gradlew "$gradle" "$work/consumer-$v" "$work/gradle-home-consumer-$v" build
		cp -r "$work/consumer-$v" "$state/"
	done

	step "deploys to $proxy are refused"
	[ "$(status -u "$E2E_USER" -T "$state/flint-e2e-lib-1.0.0.jar" "$base/$proxy/$group/x/1.0/x-1.0.jar")" = 405 ] ||
		fail "a deploy to $proxy was not refused with 405"

	step "a deleted file's name can never be used again"
	sources=$base/$releases/$group/flint-e2e-lib/1.0.0/flint-e2e-lib-1.0.0-sources.jar
	[ "$(status -u "$E2E_ADMIN" -X DELETE "$sources")" = 204 ] || fail "deleting the sources jar failed"
	[ "$(status "$base/$virtual/$group/flint-e2e-lib/1.0.0/flint-e2e-lib-1.0.0-sources.jar")" = 404 ] ||
		fail "a deleted file is still served"
	[ "$(status -u "$E2E_USER" -T "$work/flint-e2e-lib-1.0.0-sources.jar" "$sources")" = 409 ] || fail "a deleted file name was reused"

	step "dependency-confusion protection: okio in $releases hides Maven Central's"
	okio=com/squareup/okio/okio
	[ "$(status "$base/$proxy/$okio/3.9.1/okio-3.9.1.pom")" = 200 ] || fail "$proxy does not serve okio 3.9.1"
	printf '<project><modelVersion>4.0.0</modelVersion><groupId>com.squareup.okio</groupId><artifactId>okio</artifactId><version>0.0.1-flint</version></project>' \
		>"$work/okio.pom"
	[ "$(status -u "$E2E_USER" -T "$work/okio.pom" "$base/$releases/$okio/0.0.1-flint/okio-0.0.1-flint.pom")" = 201 ] ||
		fail "could not deploy okio to $releases"
	md=$(curl -fsS "$base/$virtual/$okio/maven-metadata.xml")
	grep -q '<version>0.0.1-flint</version>' <<<"$md" && ! grep -q '<version>3.9.1</version>' <<<"$md" ||
		fail "$virtual merges Maven Central's versions of okio: $md"
	[ "$(status "$base/$virtual/$okio/3.9.1/okio-3.9.1.pom")" = 404 ] || fail "$virtual serves Maven Central's okio"

	echo "OK: deployed, published, built, and proxied"
	exit 0
fi

step "flint answers with its upstream unreachable"
[ "$(status "$base/$proxy/com/squareup/okhttp3/okhttp/4.12.0/okhttp-4.12.0.jar")" = 503 ] ||
	fail "a file never cached did not fail with 503"

step "mvn builds the project again through $virtual with an empty local repository"
mvnw "$state/app" "$work/m2-offline" package
[ -f "$work/m2-offline/com/google/guava/guava/33.4.0-jre/guava-33.4.0-jre.jar" ] || fail "guava was not resolved offline"

for gradle in "${gradles[@]}"; do
	v=$(major "$gradle")
	step "Gradle $v builds the second project again with an empty Gradle home"
	gradlew "$gradle" "$state/consumer-$v" "$work/gradle-home-offline-$v" build
done
hits=$(metric "flint_proxy_requests_total{repository=\"$proxy\",result=\"hit\"}")
[ "${hits%.*}" -gt 0 ] || fail "nothing was served from the cache"
echo "OK: served from the cache"
