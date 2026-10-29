#include <boost/test/unit_test.hpp>

#include <modules/fs/posix/nm_fs_posix.h>

#include <dirent.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <set>
#include <string>
#include <vector>

namespace {

class TempDir {
 public:
    TempDir()
    {
        char tmpl[] = "/tmp/nm_fs_posix_test.XXXXXX";
        char* dir = mkdtemp(tmpl);
        BOOST_REQUIRE(dir != NULL);
        path_ = dir;
    }

    ~TempDir()
    {
        // The entries are files or empty directories.
        for (const auto& name : list()) {
            std::string entry = path_ + "/" + name;
            if (unlink(entry.c_str()) != 0) {
                rmdir(entry.c_str());
            }
        }
        rmdir(path_.c_str());
    }

    std::string file(const std::string& name) const { return path_ + "/" + name; }

    std::set<std::string> list() const
    {
        std::set<std::string> names;
        DIR* d = opendir(path_.c_str());
        BOOST_REQUIRE(d != NULL);
        while (struct dirent* e = readdir(d)) {
            std::string name = e->d_name;
            if (name != "." && name != "..") {
                names.insert(name);
            }
        }
        closedir(d);
        return names;
    }

 private:
    std::string path_;
};

std::string read_all(struct nm_fs& fs, const std::string& path)
{
    std::vector<char> buffer(256);
    size_t length = 0;
    BOOST_TEST(fs.read_file(fs.impl, path.c_str(), buffer.data(), buffer.size(), &length) == NM_FS_OK);
    return std::string(buffer.data(), length);
}

enum nm_fs_error write_string(struct nm_fs& fs, const std::string& path, const std::string& content)
{
    return fs.write_file(fs.impl, path.c_str(), (const uint8_t*)content.data(), content.size());
}

} // namespace

BOOST_AUTO_TEST_SUITE(fs_posix)

BOOST_AUTO_TEST_CASE(written_file_is_only_accessible_by_the_owner)
{
    struct nm_fs fs = nm_fs_posix_get_impl();
    TempDir dir;

    // A permissive umask must not make the file readable by others.
    mode_t oldMask = umask(0);
    enum nm_fs_error ec = write_string(fs, dir.file("device.key"), "private key");
    umask(oldMask);
    BOOST_TEST(ec == NM_FS_OK);

    struct stat st;
    BOOST_REQUIRE(stat(dir.file("device.key").c_str(), &st) == 0);
    BOOST_TEST((unsigned)(st.st_mode & 0777) == 0600u);
    BOOST_TEST(read_all(fs, dir.file("device.key")) == "private key");
}

BOOST_AUTO_TEST_CASE(overwrite_replaces_the_content_and_leaves_no_temporary_file)
{
    struct nm_fs fs = nm_fs_posix_get_impl();
    TempDir dir;

    BOOST_TEST(write_string(fs, dir.file("device.key"), "a long first content") == NM_FS_OK);
    BOOST_TEST(write_string(fs, dir.file("device.key"), "second") == NM_FS_OK);

    BOOST_TEST(read_all(fs, dir.file("device.key")) == "second");
    BOOST_TEST((dir.list() == std::set<std::string>{ "device.key" }));
}

BOOST_AUTO_TEST_CASE(failed_write_leaves_no_temporary_file)
{
    struct nm_fs fs = nm_fs_posix_get_impl();
    TempDir dir;

    // The target is a directory so the final rename fails.
    BOOST_TEST(mkdir(dir.file("target").c_str(), 0700) == 0);
    BOOST_TEST(write_string(fs, dir.file("target"), "content") != NM_FS_OK);
    BOOST_TEST((dir.list() == std::set<std::string>{ "target" }));

    // The directory of the target does not exist.
    BOOST_TEST(write_string(fs, dir.file("missing/device.key"), "content") != NM_FS_OK);
}

BOOST_AUTO_TEST_SUITE_END()
