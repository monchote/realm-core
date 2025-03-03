////////////////////////////////////////////////////////////////////////////
//
// Copyright 2015 Realm Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////

#ifndef REALM_REALM_HPP
#define REALM_REALM_HPP

#include <realm/object-store/schema.hpp>

#include <realm/util/optional.hpp>
#include <realm/binary_data.hpp>
#include <realm/db.hpp>
#include <realm/version_id.hpp>

#include <memory>

namespace realm {
class AsyncOpenTask;
class AuditInterface;
class BindingContext;
class DB;
class Group;
class Obj;
class Realm;
class Replication;
class StringData;
class Table;
class ThreadSafeReference;
class Transaction;
struct SyncConfig;
typedef std::shared_ptr<Realm> SharedRealm;
typedef std::weak_ptr<Realm> WeakRealm;

namespace util {
class Scheduler;
}

namespace _impl {
class AnyHandover;
class CollectionNotifier;
class RealmCoordinator;
class RealmFriend;
} // namespace _impl

// How to handle update_schema() being called on a file which has
// already been initialized with a different schema
enum class SchemaMode : uint8_t {
    // If the schema version has increased, automatically apply all
    // changes, then call the migration function.
    //
    // If the schema version has not changed, verify that the only
    // changes are to add new tables and add or remove indexes, and then
    // apply them if so. Does not call the migration function.
    //
    // This mode does not automatically remove tables which are not
    // present in the schema that must be manually done in the migration
    // function, to support sharing a Realm file between processes using
    // different class subsets.
    //
    // This mode allows using schemata with different subsets of tables
    // on different threads, but the tables which are shared must be
    // identical.
    Automatic,

    // Open the file in immutable mode. Schema version must match the
    // version in the file, and all tables present in the file must
    // exactly match the specified schema, except for indexes. Tables
    // are allowed to be missing from the file.
    // WARNING: This is the original ReadOnly mode.
    Immutable,

    // Open the Realm in read-only mode, transactions are not allowed to
    // be performed on the Realm instance. The schema of the existing Realm
    // file won't be changed through this Realm instance. Extra tables and
    // extra properties are allowed in the existing Realm schema. The
    // difference of indexes is allowed as well. Other schema differences
    // than those will cause an exception. This is different from Immutable
    // mode, sync Realm can be opened with ReadOnly mode. Changes
    // can be made to the Realm file through another writable Realm instance.
    // Thus, notifications are also allowed in this mode.
    // FIXME: Rename this to ReadOnly
    // WARNING: This is not the original ReadOnly mode. The original ReadOnly
    // has been renamed to Immutable.
    ReadOnlyAlternative,

    // If the schema version matches and the only schema changes are new
    // tables and indexes being added or removed, apply the changes to
    // the existing file.
    // Otherwise delete the file and recreate it from scratch.
    // The migration function is not used.
    //
    // This mode allows using schemata with different subsets of tables
    // on different threads, but the tables which are shared must be
    // identical.
    ResetFile,

    // The only changes allowed are to add new tables, add columns to
    // existing tables, and to add or remove indexes from existing
    // columns. Extra tables not present in the schema are ignored.
    // Indexes are only added to or removed from existing columns if the
    // schema version is greater than the existing one (and unlike other
    // modes, the schema version is allowed to be less than the existing
    // one).
    // The migration function is not used.
    // This should be used when including discovered user classes.
    // Previously called Additive.
    //
    // This mode allows updating the schema with additive changes even
    // if the Realm is already open on another thread.
    AdditiveDiscovered,

    // The same additive properties as AdditiveDiscovered, except
    // in this mode, all classes in the schema have been explicitly
    // included by the user. This means that stricter schema checks are
    // run such as throwing an error when an embedded object type which
    // is not linked from any top level object types is included.
    AdditiveExplicit,

    // Verify that the schema version has increased, call the migraiton
    // function, and then verify that the schema now matches.
    // The migration function is mandatory for this mode.
    //
    // This mode requires that all threads and processes which open a
    // file use identical schemata.
    Manual
};

class Realm : public std::enable_shared_from_this<Realm> {
public:
    // A callback function to be called during a migration for Automatic and
    // Manual schema modes. It is passed a SharedRealm at the version before
    // the migration, the SharedRealm in the migration, and a mutable reference
    // to the realm's Schema. Updating the schema with changes made within the
    // migration function is only required if you wish to use the ObjectStore
    // functions which take a Schema from within the migration function.
    using MigrationFunction = std::function<void(SharedRealm old_realm, SharedRealm realm, Schema&)>;

    // A callback function to be called the first time when a schema is created.
    // It is passed a SharedRealm which is in a write transaction with the schema
    // initialized. So it is possible to create some initial objects inside the callback
    // with the given SharedRealm. Those changes will be committed together with the
    // schema creation in a single transaction.
    using DataInitializationFunction = std::function<void(SharedRealm realm)>;

    // A callback function called when opening a SharedRealm when no cached
    // version of this Realm exists. It is passed the total bytes allocated for
    // the file (file size) and the total bytes used by data in the file.
    // Return `true` to indicate that an attempt to compact the file should be made
    // if it is possible to do so.
    // Won't compact the file if another process is accessing it.
    //
    // WARNING / FIXME: compact() should NOT be exposed publicly on Windows
    // because it's not crash safe! It may corrupt your database if something fails
    using ShouldCompactOnLaunchFunction = std::function<bool(uint64_t total_bytes, uint64_t used_bytes)>;

    struct Config {
        // Path and binary data are mutually exclusive
        std::string path;
        BinaryData realm_data;
        // User-supplied encryption key. Must be either empty or 64 bytes.
        std::vector<char> encryption_key;

        // Core and Object Store will in some cases need to create named pipes alongside the Realm file.
        // But on some filesystems this can be a problem (e.g. external storage on Android that uses FAT32).
        // In order to work around this, a separate path can be specified for these files.
        std::string fifo_files_fallback_path;

        bool in_memory = false;
        SchemaMode schema_mode = SchemaMode::Automatic;

        // Optional schema for the file.
        // If the schema and schema version are supplied, update_schema() is
        // called with the supplied schema, version and migration function when
        // the Realm is actually opened and not just retrieved from the cache
        util::Optional<Schema> schema;
        uint64_t schema_version = uint64_t(-1);
        MigrationFunction migration_function;

        DataInitializationFunction initialization_function;

        // A callback function called when opening a SharedRealm when no cached
        // version of this Realm exists. It is passed the total bytes allocated for
        // the file (file size) and the total bytes used by data in the file.
        // Return `true` to indicate that an attempt to compact the file should be made
        // if it is possible to do so.
        // Won't compact the file if another process is accessing it.
        //
        // WARNING / FIXME: compact() should NOT be exposed publicly on Windows
        // because it's not crash safe! It may corrupt your database if something fails
        ShouldCompactOnLaunchFunction should_compact_on_launch_function;

        // WARNING: The original read_only() has been renamed to immutable().
        bool immutable() const
        {
            return schema_mode == SchemaMode::Immutable;
        }
        // FIXME: Rename this to read_only().
        bool read_only_alternative() const
        {
            return schema_mode == SchemaMode::ReadOnlyAlternative;
        }

        // The following are intended for internal/testing purposes and
        // should not be publicly exposed in binding APIs

        // If false, always return a new Realm instance, and don't return
        // that Realm instance for other requests for a cached Realm. Useful
        // for dynamic Realms and for tests that need multiple instances on
        // one thread
        bool cache = false;

        // Throw an exception rather than automatically upgrading the file
        // format. Used by the browser to warn the user that it'll modify
        // the file.
        bool disable_format_upgrade = false;
        // Disable the background worker thread for producing change
        // notifications. Useful for tests for those notifications so that
        // everything can be done deterministically on one thread, and
        // speeds up tests that don't need notifications.
        bool automatic_change_notifications = true;

        // The Scheduler which this Realm should be bound to. If not supplied,
        // a default one for the current thread will be used.
        std::shared_ptr<util::Scheduler> scheduler;

        /// A data structure storing data used to configure the Realm for sync support.
        std::shared_ptr<SyncConfig> sync_config;

        // Open the Realm using the sync history mode even if a sync
        // configuration is not supplied.
        bool force_sync_history = false;

        // A factory function which produces an audit implementation.
        std::function<std::shared_ptr<AuditInterface>()> audit_factory;

        // Maximum number of active versions in the Realm file allowed before an exception
        // is thrown.
        uint_fast64_t max_number_of_active_versions = std::numeric_limits<uint_fast64_t>::max();

        // Disable automatic backup at file format upgrade by setting to false
        bool backup_at_file_format_change = true;
    };

    // Returns a thread-confined live Realm for the given configuration
    static SharedRealm get_shared_realm(Config config);

    // Get a Realm for the given scheduler (or current thread if `none`)
    // from the thread safe reference.
    static SharedRealm get_shared_realm(ThreadSafeReference, std::shared_ptr<util::Scheduler> = nullptr);

#if REALM_ENABLE_SYNC
    // Open a synchronized Realm and make sure it is fully up to date before
    // returning it.
    //
    // It is possible to both cancel the download and listen to download progress
    // using the `AsyncOpenTask` returned. Note that the download doesn't actually
    // start until you call `AsyncOpenTask::start(callback)`
    static std::shared_ptr<AsyncOpenTask> get_synchronized_realm(Config config);
#endif
    // Returns a frozen Realm for the given Realm. This Realm can be accessed from any thread.
    static SharedRealm get_frozen_realm(Config config, VersionID version);

    // Updates a Realm to a given schema, using the Realm's pre-set schema mode.
    void update_schema(Schema schema, uint64_t version = 0, MigrationFunction migration_function = nullptr,
                       DataInitializationFunction initialization_function = nullptr, bool in_transaction = false);

    // Set the schema used for this Realm, but do not update the file's schema
    // if it is not compatible (and instead throw an error).
    // Cannot be called multiple times on a single Realm instance or an instance
    // which has already had update_schema() called on it.
    void set_schema_subset(Schema schema);

    // Read the schema version from the file specified by the given config, or
    // ObjectStore::NotVersioned if it does not exist
    static uint64_t get_schema_version(Config const& config);

    Config const& config() const
    {
        return m_config;
    }
    Schema const& schema() const
    {
        return m_schema;
    }
    uint64_t schema_version() const
    {
        return m_schema_version;
    }

    void begin_transaction();
    void commit_transaction();
    void cancel_transaction();
    bool is_in_transaction() const noexcept;

    // Returns a frozen copy for the current version of this Realm
    // If called from within a write transaction, the returned Realm will
    // reflect the state at the beginning of the write transaction. Any
    // accumulated state changes will not be part of it. To obtain a frozen
    // transaction reflecting a current write transaction, you need to first
    // commit the write and then freeze.
    // possible better name: freeze_at_transaction_start ?
    SharedRealm freeze();

    // Returns `true` if the Realm is frozen, `false` otherwise.
    bool is_frozen() const;

    // Returns true if the Realm is either in a read or frozen transaction
    bool is_in_read_transaction() const
    {
        return m_transaction != nullptr;
    }
    uint64_t last_seen_transaction_version()
    {
        return m_schema_transaction_version;
    }

    // Returns the number of versions in the Realm file.
    uint_fast64_t get_number_of_versions() const;

    VersionID read_transaction_version() const;
    Group& read_group();
    // Get the version of the current read or frozen transaction, or `none` if the Realm
    // is not in a read transaction
    util::Optional<VersionID> current_transaction_version() const;

    TransactionRef duplicate() const;

    void enable_wait_for_change();
    bool wait_for_change();
    void wait_for_change_release();

    bool is_in_migration() const noexcept
    {
        return m_in_migration;
    }

    bool refresh();
    void set_auto_refresh(bool auto_refresh);
    bool auto_refresh() const
    {
        return m_auto_refresh;
    }
    void notify();

    void invalidate();

    // WARNING / FIXME: compact() should NOT be exposed publicly on Windows
    // because it's not crash safe! It may corrupt your database if something fails
    bool compact();
    // For synchronized realms, the file written will have the client file ident removed. Furthermore
    // it is required that all local changes are synchronized with the server before the copy can
    // be written. This is to be sure that the file can be used as a stating point for a newly
    // installed application. The function will throw if there are pending uploads.
    void write_copy(StringData path, BinaryData encryption_key);
    OwnedBinaryData write_copy();

    void verify_thread() const;
    void verify_in_write() const;
    void verify_open() const;
    bool verify_notifications_available(bool throw_on_error = true) const;

    bool can_deliver_notifications() const noexcept;
    std::shared_ptr<util::Scheduler> scheduler() const noexcept
    {
        return m_scheduler;
    }

    // Close this Realm. Continuing to use a Realm after closing it will throw ClosedRealmException
    void close();
    bool is_closed() const
    {
        return !m_transaction && !m_coordinator;
    }

    /**
     * Deletes the following files for the given `realm_file_path` if they exist:
     * - the Realm file itself
     * - the .management folder
     * - the .note file
     * - the .log file and its legacy versions: .log_a and .log_b
     *
     * The .lock file for this Realm cannot and will not be deleted as this is unsafe.
     * If a different process / thread is accessing the Realm at the same time a corrupt state
     * could be the result and checking for a single process state is not possible here.
     *
     * @param realm_file_path The path to the Realm file. All files will be derived from this.
     * @param[out] did_delete_realm If non-null, set to true if the primary Realm file was deleted.
     *
     * @throws PermissionDenied if the operation was not permitted.
     * @throws AccessError for any other error while trying to delete the file or folder.
     * @throws DeleteOnOpenRealmException if the function was called on an open Realm.
     */
    static void delete_files(const std::string& realm_file_path, bool* did_delete_realm = nullptr);

    // returns the file format version upgraded from if an upgrade took place
    util::Optional<int> file_format_upgraded_from_version() const;

    Realm(const Realm&) = delete;
    Realm& operator=(const Realm&) = delete;
    Realm(Realm&&) = delete;
    Realm& operator=(Realm&&) = delete;
    ~Realm();

    AuditInterface* audit_context() const noexcept;

    template <typename... Args>
    auto import_copy_of(Args&&... args)
    {
        return transaction().import_copy_of(std::forward<Args>(args)...);
    }

    static SharedRealm make_shared_realm(Config config, util::Optional<VersionID> version,
                                         std::shared_ptr<_impl::RealmCoordinator> coordinator)
    {
        return std::make_shared<Realm>(std::move(config), std::move(version), std::move(coordinator),
                                       MakeSharedTag{});
    }

    // Expose some internal functionality to other parts of the ObjectStore
    // without making it public to everyone
    class Internal {
        friend class _impl::CollectionNotifier;
        friend class _impl::RealmCoordinator;
        friend class TestHelper;
        friend class ThreadSafeReference;

        static Transaction& get_transaction(Realm& realm)
        {
            return realm.transaction();
        }
        static std::shared_ptr<Transaction> get_transaction_ref(Realm& realm)
        {
            return realm.transaction_ref();
        }

        // CollectionNotifier needs to be able to access the owning
        // coordinator to wake up the worker thread when a callback is
        // added, and coordinators need to be able to get themselves from a Realm
        static _impl::RealmCoordinator& get_coordinator(Realm& realm)
        {
            return *realm.m_coordinator;
        }

        static std::shared_ptr<DB>& get_db(Realm& realm);
        static void begin_read(Realm&, VersionID);
    };

private:
    struct MakeSharedTag {
    };

    std::shared_ptr<_impl::RealmCoordinator> m_coordinator;

    Config m_config;
    util::Optional<VersionID> m_frozen_version;
    std::shared_ptr<util::Scheduler> m_scheduler;
    bool m_auto_refresh = true;

    TransactionRef m_transaction;

    uint64_t m_schema_version;
    Schema m_schema;
    util::Optional<Schema> m_new_schema;
    uint64_t m_schema_transaction_version = -1;

    // FIXME: this should be a Dynamic schema mode instead, but only once
    // that's actually fully working
    bool m_dynamic_schema = true;

    // Non-zero while sending the notifications caused by advancing the read
    // transaction version, to avoid recursive notifications where possible
    size_t m_is_sending_notifications = 0;

    // True while we're performing a schema migration via this Realm instance
    // to allow for different behavior (such as allowing modifications to
    // primary key values)
    bool m_in_migration = false;

    void begin_read(VersionID);
    bool do_refresh();

    void set_schema(Schema const& reference, Schema schema);
    bool reset_file(Schema& schema, std::vector<SchemaChange>& changes_required);
    bool schema_change_needs_write_transaction(Schema& schema, std::vector<SchemaChange>& changes, uint64_t version);
    Schema get_full_schema();

    // Ensure that m_schema and m_schema_version match that of the current
    // version of the file
    void read_schema_from_group_if_needed();

    void add_schema_change_handler();
    void cache_new_schema();
    void translate_schema_error();
    void notify_schema_changed();

    Transaction& transaction();
    Transaction& transaction() const;
    std::shared_ptr<Transaction> transaction_ref();

public:
    std::unique_ptr<BindingContext> m_binding_context;

    // `enable_shared_from_this` is unsafe with public constructors; use `make_shared_realm` instead
    Realm(Config config, util::Optional<VersionID> version, std::shared_ptr<_impl::RealmCoordinator> coordinator,
          MakeSharedTag);
};

class RealmFileException : public std::runtime_error {
public:
    enum class Kind {
        /** Thrown for any I/O related exception scenarios when a realm is opened. */
        AccessError,
        /** Thrown if the history type of the on-disk Realm is unexpected or incompatible. */
        BadHistoryError,
        /** Thrown if the user does not have permission to open or create
         the specified file in the specified access mode when the realm is opened. */
        PermissionDenied,
        /** Thrown if create_Always was specified and the file did already exist when the realm is opened. */
        Exists,
        /** Thrown if no_create was specified and the file was not found when the realm is opened. */
        NotFound,
        /** Thrown if the database file is currently open in another
         process which cannot share with the current process due to an
         architecture mismatch. */
        IncompatibleLockFile,
        /** Thrown if the file needs to be upgraded to a new format, but upgrades have been explicitly disabled. */
        FormatUpgradeRequired,
    };
    RealmFileException(Kind kind, std::string path, std::string message, std::string underlying)
        : std::runtime_error(std::move(message))
        , m_kind(kind)
        , m_path(std::move(path))
        , m_underlying(std::move(underlying))
    {
    }
    Kind kind() const
    {
        return m_kind;
    }
    const std::string& path() const
    {
        return m_path;
    }
    const std::string& underlying() const
    {
        return m_underlying;
    }

private:
    Kind m_kind;
    std::string m_path;
    std::string m_underlying;
};

class MismatchedConfigException : public std::logic_error {
public:
    MismatchedConfigException(StringData message, StringData path);
};

class MismatchedRealmException : public std::logic_error {
public:
    MismatchedRealmException(StringData message);
};

class InvalidTransactionException : public std::logic_error {
public:
    InvalidTransactionException(std::string message)
        : std::logic_error(message)
    {
    }
};

class IncorrectThreadException : public std::logic_error {
public:
    IncorrectThreadException()
        : std::logic_error("Realm accessed from incorrect thread.")
    {
    }
};

class ClosedRealmException : public std::logic_error {
public:
    ClosedRealmException()
        : std::logic_error("Cannot access realm that has been closed.")
    {
    }
};

class DeleteOnOpenRealmException : public std::logic_error {
public:
    DeleteOnOpenRealmException(const std::string& path)
        : std::logic_error(util::format("Cannot delete files of an open Realm: '%1' is still in use.", path))
    {
    }
};

class UninitializedRealmException : public std::runtime_error {
public:
    UninitializedRealmException(std::string message)
        : std::runtime_error(message)
    {
    }
};

class InvalidEncryptionKeyException : public std::logic_error {
public:
    InvalidEncryptionKeyException()
        : std::logic_error("Encryption key must be 64 bytes.")
    {
    }
};
} // namespace realm

#endif /* defined(REALM_REALM_HPP) */
