#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>

namespace pcap {
  enum class magic : uint32_t {
    microseconds = 0xa1b2c3d4,
    nanoseconds = 0xa1b23c4d
  };

  static constexpr const uint16_t version_major = 2;
  static constexpr const uint16_t version_minor = 4;

  struct pcap_file_header {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
  };

  struct timeval {
    uint32_t tv_sec;
    uint32_t tv_usec;
  };

  struct pcap_pkthdr {
    timeval ts;
    uint32_t caplen;
    uint32_t len;
  };

  // Minimum size of a PCAP file.
  static constexpr const size_t
         minimum_size = sizeof(pcap_file_header) + sizeof(pcap_pkthdr);

  // PCAP file.
  struct file {
    // File name.
    char* filename;

    // File size.
    uint64_t filesize;

    // Timestamp of the first packet.
    uint64_t timestamp;
  };

  // List of PCAP files.
  class files {
    public:
      // Constructor.
      files() = default;

      // Destructor.
      ~files()
      {
        if (_M_files) {
          for (; _M_used > 0; _M_used--) {
            free(_M_files[_M_used - 1].filename);
          }

          free(_M_files);
        }
      }

      // Add PCAP file.
      bool add(const char* filename, uint64_t filesize, uint64_t timestamp)
      {
        // Allocate new PCAP files (if needed).
        if (allocate()) {
          char* f;
          if ((f = strdup(filename)) != nullptr) {
            file* entry = &_M_files[_M_used++];

            entry->filename = f;
            entry->filesize = filesize;
            entry->timestamp = timestamp;

            return true;
          }
        }

        return false;
      }

      // Sort.
      void sort()
      {
        qsort(_M_files, _M_used, sizeof(file), compare);
      }

      // Get PCAP file.
      const file* get(size_t idx) const
      {
        return (idx < _M_used) ? &_M_files[idx] : nullptr;
      }

    private:
      // PCAP files.
      file* _M_files = nullptr;
      size_t _M_size = 0;
      size_t _M_used = 0;

      // Allocate.
      bool allocate()
      {
        if (_M_used < _M_size) {
          return true;
        } else {
          size_t size = (_M_size > 0) ? _M_size * 2 : 1024;

          file* files;
          if ((files = static_cast<file*>(
                         realloc(_M_files, size * sizeof(file))
                       )) != nullptr) {
            _M_files = files;
            _M_size = size;

            return true;
          } else {
            return false;
          }
        }
      }

      static int compare(const void* p1, const void* p2)
      {
        const file* const f1 = static_cast<const file*>(p1);
        const file* const f2 = static_cast<const file*>(p2);

        if (f1->timestamp < f2->timestamp) {
          return -1;
        } else if (f1->timestamp > f2->timestamp) {
          return 1;
        } else {
          return 0;
        }
      }
  };
}

static void usage(const char* program);
static bool get_first_timestamp(const char* filename, uint64_t& timestamp);
static bool copy_file(int outfd,
                      const char* filename,
                      uint64_t filesize,
                      size_t offset);

int main(int argc, const char** argv)
{
  // Check usage.
  if (argc == 3) {
    // If it is a directory...
    struct stat sbuf;
    if ((stat(argv[1], &sbuf) == 0) && (S_ISDIR(sbuf.st_mode))) {
      // Open output file for writing.
      int fd;
      if ((fd = open(argv[2], O_CREAT | O_TRUNC | O_WRONLY, 0644)) != -1) {
        // Open directory.
        DIR* dir;
        if ((dir = opendir(argv[1])) != nullptr) {
          pcap::files files;

          // Size of the output file.
          uint64_t filesize = sizeof(pcap::pcap_file_header);

          struct dirent* entry;
          while ((entry = readdir(dir)) != nullptr) {
            // Compose full filename.
            char pathname[PATH_MAX];
            snprintf(pathname,
                     sizeof(pathname),
                     "%s/%s",
                     argv[1],
                     entry->d_name);

            // If it is a regular file and is not too small...
            if ((stat(pathname, &sbuf) == 0) &&
                (S_ISREG(sbuf.st_mode)) &&
                (sbuf.st_size > static_cast<off_t>(pcap::minimum_size))) {
              size_t len = strlen(entry->d_name);

              // PCAP file?
              if ((len > 5) &&
                  (entry->d_name[len - 5] == '.') &&
                  (strcasecmp(entry->d_name + len - 4, "pcap") == 0)) {
                // Get timestamp of the first packet.
                uint64_t timestamp;
                if (get_first_timestamp(pathname, timestamp)) {
                  if (files.add(pathname, sbuf.st_size, timestamp)) {
                    // Increment size of the output file.
                    filesize += (sbuf.st_size -
                                 sizeof(pcap::pcap_file_header));
                  } else {
                    fprintf(stderr, "Error allocating memory.\n");

                    closedir(dir);

                    close(fd);
                    unlink(argv[2]);

                    return -1;
                  }
                }
              }
            }
          }

          closedir(dir);

          if (ftruncate(fd, filesize) == 0) {
            // Sort PCAP files.
            files.sort();

            const pcap::file* file;
            for (size_t i = 0; (file = files.get(i)) != nullptr; i++) {
              if (!copy_file(fd,
                             file->filename,
                             file->filesize,
                             (i > 0) ? sizeof(pcap::pcap_file_header) : 0)) {
                const uint64_t
                  to_copy = (i > 0) ?
                    file->filesize - sizeof(pcap::pcap_file_header) :
                    file->filesize;

                fprintf(stderr,
                        "Error copying %" PRIu64 " bytes from '%s' to '%s'.\n",
                        to_copy,
                        file->filename,
                        argv[2]);

                close(fd);
                unlink(argv[2]);

                return -1;
              }
            }

            close(fd);

            return 0;
          } else {
            fprintf(stderr,
                    "Error truncating file '%s' to %" PRIu64 " bytes.\n",
                    argv[2],
                    filesize);
          }
        } else {
          fprintf(stderr, "Error opening directory '%s'.\n", argv[1]);
        }

        close(fd);
        unlink(argv[2]);
      } else {
        fprintf(stderr, "Error opening file '%s' for writing.\n", argv[2]);
      }
    } else {
      fprintf(stderr, "'%s' doesn't exist or is not a directory.\n", argv[1]);
    }
  } else {
    usage(argv[0]);
  }

  return -1;
}

void usage(const char* program)
{
  fprintf(stderr, "Usage: %s <directory> <filename>\n", program);
}

bool get_first_timestamp(const char* filename, uint64_t& timestamp)
{
  // Open PCAP file for reading.
  int fd;
  if ((fd = open(filename, O_RDONLY)) != -1) {
    // Read PCAP file header and the header of the first packet.
    uint8_t buf[pcap::minimum_size];
    if (read(fd, buf, pcap::minimum_size) ==
        static_cast<ssize_t>(pcap::minimum_size)) {
      const pcap::pcap_file_header* const
        filehdr = reinterpret_cast<const pcap::pcap_file_header*>(buf);

      // Check magic and version.
      if (((static_cast<pcap::magic>(filehdr->magic) ==
            pcap::magic::microseconds) ||
           (static_cast<pcap::magic>(filehdr->magic) ==
            pcap::magic::nanoseconds)) &&
          (filehdr->version_major == pcap::version_major) &&
          (filehdr->version_minor == pcap::version_minor)) {
        const pcap::pcap_pkthdr* const
          pkthdr = reinterpret_cast<const pcap::pcap_pkthdr*>(
                     buf + sizeof(pcap::pcap_file_header)
                   );

        timestamp = (pkthdr->ts.tv_sec * 1000000ull) +
                    pkthdr->ts.tv_usec;

        close(fd);

        return true;
      }
    }

    close(fd);
  }

  return false;
}

bool copy_file(int outfd,
               const char* filename,
               uint64_t filesize,
               size_t offset)
{
  // Open file for reading.
  int infd;
  if ((infd = open(filename, O_RDONLY)) != -1) {
    // Map file into memory.
    void* base;
    if ((base = mmap(nullptr,
                     filesize,
                     PROT_READ,
                     MAP_SHARED,
                     infd,
                     0)) != MAP_FAILED) {
      const uint8_t* ptr = static_cast<const uint8_t*>(base) + offset;
      const uint64_t to_copy = filesize - offset;

      uint64_t written = 0;

      do {
        ssize_t ret;
        if ((ret = write(outfd, ptr, to_copy - written)) > 0) {
          if ((written += ret) == to_copy) {
            munmap(base, filesize);
            close(infd);

            return true;
          } else {
            ptr += ret;
          }
        } else if (ret < 0) {
          if (errno != EINTR) {
            munmap(base, filesize);
            close(infd);

            return false;
          }
        }
      } while (true);
    }

    close(infd);
  }

  return false;
}
