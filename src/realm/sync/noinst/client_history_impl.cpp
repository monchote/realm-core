#include <ctime>
#include <cstring>
#include <algorithm>
#include <utility>

#include <realm/util/features.h>
#include <realm/util/scope_exit.hpp>
#include <realm/sync/noinst/client_history_impl.hpp>
#include <realm/version.hpp>
#include <realm/sync/object.hpp>
#include <realm/sync/changeset.hpp>
#include <realm/sync/changeset_parser.hpp>
#include <realm/sync/instruction_replication.hpp>
#include <realm/sync/instruction_applier.hpp>

using namespace realm;

using _impl::ClientHistoryImpl;

void ClientHistoryImpl::set_initial_state_realm_history_numbers(version_type current_version,
                                                                sync::SaltedVersion server_version)
{
    REALM_ASSERT(current_version == s_initial_version + 1);
    ensure_updated(current_version); // Throws
    prepare_for_write();             // Throws

    version_type client_version = m_sync_history_base_version + sync_history_size();
    REALM_ASSERT(client_version == current_version); // For now
    DownloadCursor download_progress = {server_version.version, 0};

    Array& root = m_arrays->root;
    root.set(s_progress_download_server_version_iip,
             RefOrTagged::make_tagged(download_progress.server_version)); // Throws
    root.set(s_progress_download_client_version_iip,
             RefOrTagged::make_tagged(download_progress.last_integrated_client_version)); // Throws
    root.set(s_progress_latest_server_version_iip,
             RefOrTagged::make_tagged(server_version.version)); // Throws
    root.set(s_progress_latest_server_version_salt_iip,
             RefOrTagged::make_tagged(server_version.salt)); // Throws

    m_progress_download = download_progress;
}


void ClientHistoryImpl::make_final_async_open_adjustements(SaltedFileIdent client_file_ident,
                                                           std::uint_fast64_t downloaded_bytes)
{
    auto wt = m_db->start_write(); // Throws
    version_type local_version = wt->get_version();
    ensure_updated(local_version); // Throws
    prepare_for_write();           // Throws

    REALM_ASSERT(m_group->get_sync_file_id() == 0);

    Array& root = m_arrays->root;
    m_group->set_sync_file_id(client_file_ident.ident);                                       // Throws
    root.set(s_client_file_ident_salt_iip, RefOrTagged::make_tagged(client_file_ident.salt)); // Throws
    root.set(s_progress_downloaded_bytes_iip, RefOrTagged::make_tagged(downloaded_bytes));    // Throws

    wt->commit(); // Throws
}


void ClientHistoryImpl::set_client_file_ident_in_wt(version_type current_version, SaltedFileIdent client_file_ident)
{
    ensure_updated(current_version); // Throws
    prepare_for_write();             // Throws

    Array& root = m_arrays->root;
    m_group->set_sync_file_id(client_file_ident.ident); // Throws
    root.set(s_client_file_ident_salt_iip,
             RefOrTagged::make_tagged(client_file_ident.salt)); // Throws
}


auto ClientHistoryImpl::get_next_local_changeset(version_type current_version, version_type begin_version) const
    -> util::Optional<LocalChangeset>
{
    ensure_updated(current_version); // Throws

    if (!m_arrays)
        return none;
    REALM_ASSERT(begin_version >= 1);
    version_type end_version = m_sync_history_base_version + sync_history_size();
    if (begin_version < m_sync_history_base_version)
        begin_version = m_sync_history_base_version;

    for (version_type version = begin_version; version < end_version; ++version) {
        std::size_t ndx = std::size_t(version - m_sync_history_base_version);
        std::int_fast64_t origin_file_ident = m_arrays->origin_file_idents.get(ndx);
        bool not_from_server = (origin_file_ident == 0);
        if (not_from_server) {
            LocalChangeset local_changeset;
            local_changeset.version = version;
            ChunkedBinaryData changeset(m_arrays->changesets, ndx);
            local_changeset.changeset = changeset;
            return local_changeset;
        }
    }
    return none;
}


void ClientHistoryImpl::set_client_reset_adjustments(version_type current_version, SaltedFileIdent client_file_ident,
                                                     sync::SaltedVersion server_version,
                                                     std::uint_fast64_t downloaded_bytes,
                                                     BinaryData uploadable_changeset)
{
    ensure_updated(current_version); // Throws
    prepare_for_write();             // Throws

    version_type client_version = m_sync_history_base_version + sync_history_size();
    REALM_ASSERT(client_version == current_version); // For now
    DownloadCursor download_progress = {server_version.version, 0};
    UploadCursor upload_progress = {0, 0};
    Array& root = m_arrays->root;
    m_group->set_sync_file_id(client_file_ident.ident); // Throws
    root.set(s_client_file_ident_salt_iip,
             RefOrTagged::make_tagged(client_file_ident.salt)); // Throws
    root.set(s_progress_download_server_version_iip,
             RefOrTagged::make_tagged(download_progress.server_version)); // Throws
    root.set(s_progress_download_client_version_iip,
             RefOrTagged::make_tagged(download_progress.last_integrated_client_version)); // Throws
    root.set(s_progress_latest_server_version_iip,
             RefOrTagged::make_tagged(server_version.version)); // Throws
    root.set(s_progress_latest_server_version_salt_iip,
             RefOrTagged::make_tagged(server_version.salt)); // Throws
    root.set(s_progress_upload_client_version_iip,
             RefOrTagged::make_tagged(upload_progress.client_version)); // Throws
    root.set(s_progress_upload_server_version_iip,
             RefOrTagged::make_tagged(upload_progress.last_integrated_server_version)); // Throws
    root.set(s_progress_downloaded_bytes_iip,
             RefOrTagged::make_tagged(downloaded_bytes)); // Throws
    root.set(s_progress_downloadable_bytes_iip,
             RefOrTagged::make_tagged(0)); // Throws
    root.set(s_progress_uploaded_bytes_iip,
             RefOrTagged::make_tagged(0)); // Throws
    root.set(s_progress_uploadable_bytes_iip,
             RefOrTagged::make_tagged(0)); // Throws

    // Discard existing synchronization history
    do_trim_sync_history(sync_history_size()); // Throws

    m_progress_download = download_progress;
    m_client_reset_changeset = uploadable_changeset; // Picked up by prepare_changeset()
}


void ClientHistoryImpl::set_local_origin_timestamp_source(std::function<sync::timestamp_type()> source_fn)
{
    m_local_origin_timestamp_source = std::move(source_fn);
}

// Overriding member function in realm::Replication
void ClientHistoryImpl::initialize(DB& sg)
{
    REALM_ASSERT(!m_db);
    SyncReplication::initialize(sg); // Throws
    m_db = &sg;
}


// Overriding member function in realm::Replication
void ClientHistoryImpl::initiate_session(version_type)
{
    // No-op
}


// Overriding member function in realm::Replication
void ClientHistoryImpl::terminate_session() noexcept
{
    // No-op
}


// Overriding member function in realm::Replication
auto ClientHistoryImpl::get_history_type() const noexcept -> HistoryType
{
    return hist_SyncClient;
}


// Overriding member function in realm::Replication
int ClientHistoryImpl::get_history_schema_version() const noexcept
{
    return get_client_history_schema_version();
}


// Overriding member function in realm::Replication
bool ClientHistoryImpl::is_upgradable_history_schema(int stored_schema_version) const noexcept
{
    if (stored_schema_version == 11) {
        return true;
    }
    return false;
}


// Overriding member function in realm::Replication
void ClientHistoryImpl::upgrade_history_schema(int stored_schema_version)
{
    // upgrade_history_schema() is called only when there is a need to upgrade
    // (`stored_schema_version < get_server_history_schema_version()`), and only
    // when is_upgradable_history_schema() returned true (`stored_schema_version
    // >= 1`).
    REALM_ASSERT(stored_schema_version < get_client_history_schema_version());
    REALM_ASSERT(stored_schema_version >= 11);
    int orig_schema_version = stored_schema_version;
    int schema_version = orig_schema_version;

    // NOTE: Future migration steps go here.

    REALM_ASSERT(schema_version == get_client_history_schema_version());

    // Record migration event
    record_current_schema_version(); // Throws
}

// Overriding member function in realm::Replication
_impl::History* ClientHistoryImpl::_get_history_write()
{
    // REALM_ASSERT(m_group != nullptr);
    return this;
}

// Overriding member function in realm::Replication
std::unique_ptr<_impl::History> ClientHistoryImpl::_create_history_read()
{
    auto hist_impl = std::make_unique<ClientHistoryImpl>(get_database_path());
    hist_impl->initialize(*m_db); // Throws
    // Transfer ownership with pointer to private base class
    return std::unique_ptr<_impl::History>{hist_impl.release()};
}

// Overriding member function in realm::Replication
void ClientHistoryImpl::do_initiate_transact(Group& group, version_type version, bool history_updated)
{
    SyncReplication::do_initiate_transact(group, version, history_updated);
}

// Overriding member function in realm::TrivialReplication
auto ClientHistoryImpl::prepare_changeset(const char* data, size_t size, version_type orig_version) -> version_type
{
    ensure_updated(orig_version);
    prepare_for_write(); // Throws

    BinaryData ct_changeset{data, size};
    add_ct_history_entry(ct_changeset); // Throws

    HistoryEntry entry;

    REALM_ASSERT(!m_changeset_from_server || !m_client_reset_changeset);

    if (m_changeset_from_server) {
        entry = *std::move(m_changeset_from_server);

        REALM_ASSERT(get_instruction_encoder().buffer().size() == 0);
    }
    else {
        BinaryData changeset;
        if (m_client_reset_changeset) {
            changeset = *m_client_reset_changeset;
            m_client_reset_changeset = util::none;
        }
        else {
            auto& buffer = get_instruction_encoder().buffer();
            changeset = BinaryData(buffer.data(), buffer.size());
        }

        entry.origin_timestamp = m_local_origin_timestamp_source();
        entry.origin_file_ident = 0; // Of local origin
        entry.remote_version = m_progress_download.server_version;
        entry.changeset = changeset;

        // uploadable_bytes is updated at every local Realm change. The total
        // number of uploadable bytes must be persisted in the Realm, since the
        // synchronization history is trimmed. Even if the synchronization
        // history wasn't trimmed, it would be expensive to traverse the entire
        // history at every access to uploadable bytes.
        Array& root = m_arrays->root;
        std::uint_fast64_t uploadable_bytes = root.get_as_ref_or_tagged(s_progress_uploadable_bytes_iip).get_as_int();
        uploadable_bytes += entry.changeset.size();
        root.set(s_progress_uploadable_bytes_iip, RefOrTagged::make_tagged(uploadable_bytes));
    }

    add_sync_history_entry(entry); // Throws

    return m_ct_history_base_version + ct_history_size();
}


// Overriding member function in realm::TrivialReplication
void ClientHistoryImpl::finalize_changeset() noexcept
{
    // Since the history is in the Realm, the added changeset is
    // automatically finalized as part of the commit operation.
    m_changeset_from_server = util::none;
}

// Overriding member function in realm::sync::ClientHistoryBase
void ClientHistoryImpl::get_status(version_type& current_client_version, SaltedFileIdent& client_file_ident,
                                   SyncProgress& progress) const
{
    TransactionRef rt = m_db->start_read(); // Throws
    version_type current_client_version_2 = rt->get_version();

    SaltedFileIdent client_file_ident_2{rt->get_sync_file_id(), 0};
    SyncProgress progress_2;
    using gf = _impl::GroupFriend;
    if (ref_type ref = gf::get_history_ref(*rt)) {
        Array root(m_db->get_alloc());
        root.init_from_ref(ref);
        client_file_ident_2.salt =
            sync::salt_type(root.get_as_ref_or_tagged(s_client_file_ident_salt_iip).get_as_int());
        progress_2.latest_server_version.version =
            version_type(root.get_as_ref_or_tagged(s_progress_latest_server_version_iip).get_as_int());
        progress_2.latest_server_version.salt =
            version_type(root.get_as_ref_or_tagged(s_progress_latest_server_version_salt_iip).get_as_int());
        progress_2.download.server_version =
            version_type(root.get_as_ref_or_tagged(s_progress_download_server_version_iip).get_as_int());
        progress_2.download.last_integrated_client_version =
            version_type(root.get_as_ref_or_tagged(s_progress_download_client_version_iip).get_as_int());
        progress_2.upload.client_version =
            version_type(root.get_as_ref_or_tagged(s_progress_upload_client_version_iip).get_as_int());
        progress_2.upload.last_integrated_server_version =
            version_type(root.get_as_ref_or_tagged(s_progress_upload_server_version_iip).get_as_int());
    }

    current_client_version = current_client_version_2;
    client_file_ident = client_file_ident_2;
    progress = progress_2;

    REALM_ASSERT(current_client_version >= s_initial_version + 0);
    if (current_client_version == s_initial_version + 0)
        current_client_version = 0;
}


// Overriding member function in realm::sync::ClientHistoryBase
void ClientHistoryImpl::set_client_file_ident(SaltedFileIdent client_file_ident, bool fix_up_object_ids)
{
    REALM_ASSERT(client_file_ident.ident != 0);

    TransactionRef wt = m_db->start_write(); // Throws
    version_type local_version = wt->get_version();
    ensure_updated(local_version); // Throws
    prepare_for_write();           // Throws

    Array& root = m_arrays->root;
    REALM_ASSERT(wt->get_sync_file_id() == 0);
    wt->set_sync_file_id(client_file_ident.ident);
    root.set(s_client_file_ident_salt_iip,
             RefOrTagged::make_tagged(client_file_ident.salt)); // Throws

    if (fix_up_object_ids) {
        // Replication must be temporarily disabled because the database must be
        // modified to fix up object IDs.
        //
        // FIXME: This is dangerous, because accessors will not be updated with
        // modifications made here.  Luckily, only set_int() modifications are
        // made, which never have an impact on accessors. However, notifications
        // will not be triggered for those updates either.
        sync::TempShortCircuitReplication tscr{*this};
        fix_up_client_file_ident_in_stored_changesets(*wt, client_file_ident.ident); // Throws
    }

    // Note: This transaction produces an empty changeset. Empty changesets are
    // not uploaded to the server.
    wt->commit(); // Throws
}


// Overriding member function in realm::sync::ClientHistoryBase
void ClientHistoryImpl::set_sync_progress(const SyncProgress& progress, const std::uint_fast64_t* downloadable_bytes,
                                          VersionInfo& version_info)
{
    TransactionRef wt = m_db->start_write(); // Throws
    version_type local_version = wt->get_version();
    ensure_updated(local_version); // Throws
    prepare_for_write();           // Throws

    update_sync_progress(progress, downloadable_bytes); // Throws

    // Note: This transaction produces an empty changeset. Empty changesets are
    // not uploaded to the server.
    version_type new_version = wt->commit(); // Throws
    version_info.realm_version = new_version;
    version_info.sync_version = {new_version, 0};
}


// Overriding member function in realm::sync::ClientHistoryBase
void ClientHistoryImpl::find_uploadable_changesets(UploadCursor& upload_progress, version_type end_version,
                                                   std::vector<UploadChangeset>& uploadable_changesets,
                                                   version_type& locked_server_version) const
{
    TransactionRef rt = m_db->start_read(); // Throws
    auto& alloc = m_db->get_alloc();
    using gf = _impl::GroupFriend;
    ref_type ref = gf::get_history_ref(*rt);
    REALM_ASSERT(ref);

    Arrays arrays(alloc, *rt, ref);
    const auto sync_history_size = arrays.changesets.size();
    const auto sync_history_base_version = rt->get_version() - sync_history_size;

    std::size_t accum_byte_size_soft_limit = 0x20000; // 128 KB
    std::size_t accum_byte_size = 0;

    version_type begin_version_2 = std::max(upload_progress.client_version, sync_history_base_version);
    version_type end_version_2 = std::max(end_version, sync_history_base_version);
    version_type last_integrated_upstream_version = upload_progress.last_integrated_server_version;

    while (accum_byte_size < accum_byte_size_soft_limit) {
        HistoryEntry entry;
        version_type version = find_sync_history_entry(arrays, sync_history_base_version, begin_version_2,
                                                       end_version_2, entry, last_integrated_upstream_version);

        if (version == 0) {
            begin_version_2 = end_version_2;
            break;
        }
        begin_version_2 = version;

        UploadChangeset uc;
        std::size_t size = entry.changeset.copy_to(uc.buffer);
        uc.origin_timestamp = entry.origin_timestamp;
        uc.origin_file_ident = entry.origin_file_ident;
        uc.progress = UploadCursor{version, entry.remote_version};
        uc.changeset = BinaryData{uc.buffer.get(), size};
        uploadable_changesets.push_back(std::move(uc)); // Throws

        accum_byte_size += size;
    }

    upload_progress = {std::min(begin_version_2, end_version), last_integrated_upstream_version};

    locked_server_version = arrays.root.get_as_ref_or_tagged(s_progress_download_server_version_iip).get_as_int();
}


// Overriding member function in realm::sync::ClientHistoryBase
bool ClientHistoryImpl::integrate_server_changesets(const SyncProgress& progress,
                                                    const std::uint_fast64_t* downloadable_bytes,
                                                    const RemoteChangeset* incoming_changesets,
                                                    std::size_t num_changesets, VersionInfo& version_info,
                                                    IntegrationError& integration_error, util::Logger& logger,
                                                    SyncTransactReporter* transact_reporter)
{
    REALM_ASSERT(num_changesets != 0);

    // Changesets are applied to the Realm with replication temporarily
    // disabled. The main reason for disabling replication and manually adding
    // the transformed changesets to the history, is that the replication system
    // (due to technical debt) is unable in some cases to produce a correct
    // changeset while applying another one (i.e., it cannot carbon copy).

    VersionID old_version;
    TransactionRef transact = m_db->start_write(); // Throws
    old_version = transact->get_version_of_current_transaction();
    version_type local_version = old_version.version;

    ensure_updated(local_version); // Throws
    prepare_for_write();           // Throws

    REALM_ASSERT(transact->get_sync_file_id() != 0);

    std::vector<char> assembled_transformed_changeset;
    std::vector<sync::Changeset> changesets;
    changesets.resize(num_changesets); // Throws

    std::uint_fast64_t downloaded_bytes_in_message = 0;

    try {
        for (std::size_t i = 0; i < num_changesets; ++i) {
            const RemoteChangeset& changeset = incoming_changesets[i];
            REALM_ASSERT(changeset.last_integrated_local_version <= local_version);
            REALM_ASSERT(changeset.origin_file_ident > 0 &&
                         changeset.origin_file_ident != transact->get_sync_file_id());
            downloaded_bytes_in_message += changeset.original_changeset_size;

            sync::parse_remote_changeset(changeset, changesets[i]); // Throws

            // It is possible that the synchronization history has been trimmed
            // to a point where a prefix of the merge window is no longer
            // available, but this can only happen if that prefix consisted
            // entirely of upload skippable entries. Since such entries (those
            // that are empty or of remote origin) will be skipped by the
            // transformer anyway, we can simply clamp the beginning of the
            // merge window to the beginning of the synchronization history,
            // when this situation occurs.
            //
            // See trim_sync_history() for further details.
            if (changesets[i].last_integrated_remote_version < m_sync_history_base_version)
                changesets[i].last_integrated_remote_version = m_sync_history_base_version;
        }

        Transformer& transformer = get_transformer(); // Throws
        Transformer::Reporter* reporter = nullptr;
        transformer.transform_remote_changesets(*this, transact->get_sync_file_id(), local_version, changesets.data(),
                                                changesets.size(), reporter, &logger); // Throws

        for (std::size_t i = 0; i < num_changesets; ++i) {
            util::AppendBuffer<char> transformed_changeset;
            sync::encode_changeset(changesets[i], transformed_changeset);

            sync::InstructionApplier applier{*transact};
            {
                sync::TempShortCircuitReplication tscr{*this};
                applier.apply(changesets[i], &logger); // Throws
            }

            // The need to produce a combined changeset is unfortunate from a
            // memory pressure/allocation cost point of view. It is believed
            // that the history (list of applied changesets) will be moved into
            // the main Realm file eventually, and that would probably eliminate
            // this problem.
            std::size_t size_1 = assembled_transformed_changeset.size();
            std::size_t size_2 = size_1;
            if (util::int_add_with_overflow_detect(size_2, transformed_changeset.size()))
                throw util::overflow_error{"Changeset size overflow"};
            assembled_transformed_changeset.resize(size_2); // Throws
            std::copy(transformed_changeset.data(), transformed_changeset.data() + transformed_changeset.size(),
                      assembled_transformed_changeset.data() + size_1);
        }
    }
    catch (sync::BadChangesetError& e) {
        logger.error("Failed to parse, or apply received changeset: %1", e.what()); // Throws
        integration_error = IntegrationError::bad_changeset;
        return false;
    }
    catch (sync::TransformError& e) {
        logger.error("Failed to transform received changeset: %1", e.what()); // Throws
        integration_error = IntegrationError::bad_changeset;
        return false;
    }

    // downloaded_bytes always contains the total number of downloaded bytes
    // from the Realm. downloaded_bytes must be persisted in the Realm, since
    // the downloaded changesets are trimmed after use, and since it would be
    // expensive to traverse the entire history.
    Array& root = m_arrays->root;
    auto downloaded_bytes =
        std::uint_fast64_t(root.get_as_ref_or_tagged(s_progress_downloaded_bytes_iip).get_as_int());
    downloaded_bytes += downloaded_bytes_in_message;
    root.set(s_progress_downloaded_bytes_iip, RefOrTagged::make_tagged(downloaded_bytes)); // Throws

    // The reason we can use the `origin_timestamp`, and the `origin_file_ident`
    // from the last incoming changeset, and ignore all the other changesets, is
    // that these values are actually irrelevant for changesets of remote origin
    // stored in the client-side history (for now), except that
    // `origin_file_ident` is required to be nonzero, to mark it as having been
    // received from the server.
    const sync::Changeset& last_changeset = changesets.back();
    HistoryEntry entry;
    entry.origin_timestamp = last_changeset.origin_timestamp;
    entry.origin_file_ident = last_changeset.origin_file_ident;
    entry.remote_version = last_changeset.version;
    entry.changeset = BinaryData(assembled_transformed_changeset.data(), assembled_transformed_changeset.size());

    // m_changeset_from_server is picked up by prepare_changeset(), which then
    // calls add_sync_history_entry(). prepare_changeset() is called as a result
    // of committing the current transaction even in the "short-circuited" mode,
    // because replication isn't disabled.
    m_changeset_from_server_owner = std::move(assembled_transformed_changeset);
    REALM_ASSERT(!m_changeset_from_server);
    m_changeset_from_server = entry;

    update_sync_progress(progress, downloadable_bytes); // Throws

    version_type new_version = transact->commit_and_continue_as_read().version; // Throws

    if (transact_reporter) {
        VersionID new_version_2 = transact->get_version_of_current_transaction();
        transact_reporter->report_sync_transact(old_version, new_version_2); // Throws
    }

    version_info.realm_version = new_version;
    version_info.sync_version = {new_version, 0};
    return true;
}


// Overriding member function in realm::sync::ClientHistory
void ClientHistoryImpl::get_upload_download_bytes(std::uint_fast64_t& downloaded_bytes,
                                                  std::uint_fast64_t& downloadable_bytes,
                                                  std::uint_fast64_t& uploaded_bytes,
                                                  std::uint_fast64_t& uploadable_bytes,
                                                  std::uint_fast64_t& snapshot_version)
{
    get_upload_download_bytes(m_db, downloaded_bytes, downloadable_bytes, uploaded_bytes, uploadable_bytes,
                              snapshot_version);
}

void ClientHistoryImpl::get_upload_download_bytes(DB* db, std::uint_fast64_t& downloaded_bytes,
                                                  std::uint_fast64_t& downloadable_bytes,
                                                  std::uint_fast64_t& uploaded_bytes,
                                                  std::uint_fast64_t& uploadable_bytes,
                                                  std::uint_fast64_t& snapshot_version)
{
    TransactionRef rt = db->start_read(); // Throws
    version_type current_client_version = rt->get_version();

    downloaded_bytes = 0;
    downloadable_bytes = 0;
    uploaded_bytes = 0;
    uploadable_bytes = 0;
    snapshot_version = current_client_version;

    using gf = _impl::GroupFriend;
    if (ref_type ref = gf::get_history_ref(*rt)) {
        Array root(db->get_alloc());
        root.init_from_ref(ref);
        downloaded_bytes = root.get_as_ref_or_tagged(s_progress_downloaded_bytes_iip).get_as_int();
        downloadable_bytes = root.get_as_ref_or_tagged(s_progress_downloadable_bytes_iip).get_as_int();
        uploadable_bytes = root.get_as_ref_or_tagged(s_progress_uploadable_bytes_iip).get_as_int();
        uploaded_bytes = root.get_as_ref_or_tagged(s_progress_uploaded_bytes_iip).get_as_int();
    }
}

// Overriding member function in realm::sync::ClientHistory
auto ClientHistoryImpl::get_upload_anchor_of_current_transact(const Transaction& tr) const -> UploadCursor
{
    REALM_ASSERT(tr.get_transact_stage() != DB::transact_Ready);
    version_type current_version = tr.get_version();
    ensure_updated(current_version); // Throws
    UploadCursor upload_anchor;
    upload_anchor.client_version = current_version;
    upload_anchor.last_integrated_server_version = m_progress_download.server_version;
    return upload_anchor;
}

// Overriding member function in realm::sync::ClientHistory
util::StringView ClientHistoryImpl::get_sync_changeset_of_current_transact(const Transaction& tr) const noexcept
{
    REALM_ASSERT(tr.get_transact_stage() == DB::transact_Writing);
    const sync::ChangesetEncoder& encoder = get_instruction_encoder();
    const sync::ChangesetEncoder::Buffer& buffer = encoder.buffer();
    return {buffer.data(), buffer.size()};
}

// Overriding member function in realm::sync::TransformHistory
auto ClientHistoryImpl::find_history_entry(version_type begin_version, version_type end_version,
                                           HistoryEntry& entry) const noexcept -> version_type
{
    version_type last_integrated_server_version;
    return find_sync_history_entry(*m_arrays, m_sync_history_base_version, begin_version, end_version, entry,
                                   last_integrated_server_version);
}


// Overriding member function in realm::sync::TransformHistory
ChunkedBinaryData ClientHistoryImpl::get_reciprocal_transform(version_type version) const
{
    REALM_ASSERT(version > m_sync_history_base_version);

    std::size_t index = to_size_t(version - m_sync_history_base_version) - 1;
    REALM_ASSERT(index < sync_history_size());

    ChunkedBinaryData reciprocal{m_arrays->reciprocal_transforms, index};
    if (!reciprocal.is_null())
        return reciprocal;
    return ChunkedBinaryData{m_arrays->changesets, index};
}


// Overriding member function in realm::sync::TransformHistory
void ClientHistoryImpl::set_reciprocal_transform(version_type version, BinaryData data)
{
    REALM_ASSERT(version > m_sync_history_base_version);

    std::size_t index = size_t(version - m_sync_history_base_version) - 1;
    REALM_ASSERT(index < sync_history_size());

    // FIXME: BinaryColumn::set() currently interprets BinaryData(0,0) as
    // null. It should probably be changed such that BinaryData(0,0) is always
    // interpreted as the empty string. For the purpose of setting null values,
    // BinaryColumn::set() should accept values of type Optional<BinaryData>().
    BinaryData data_2 = (data ? data : BinaryData("", 0));
    m_arrays->reciprocal_transforms.set(index, data_2); // Throws
}


auto ClientHistoryImpl::find_sync_history_entry(Arrays& arrays, version_type base_version, version_type begin_version,
                                                version_type end_version, HistoryEntry& entry,
                                                version_type& last_integrated_server_version) noexcept -> version_type
{
    if (begin_version == 0)
        begin_version = s_initial_version + 0;

    REALM_ASSERT(begin_version <= end_version);
    REALM_ASSERT(begin_version >= base_version);
    REALM_ASSERT(end_version <= base_version + arrays.changesets.size());
    std::size_t n = to_size_t(end_version - begin_version);
    std::size_t offset = to_size_t(begin_version - base_version);
    for (std::size_t i = 0; i < n; ++i) {
        std::int_fast64_t origin_file_ident = arrays.origin_file_idents.get(offset + i);
        last_integrated_server_version = version_type(arrays.remote_versions.get(offset + i));
        bool not_from_server = (origin_file_ident == 0);
        if (not_from_server) {
            ChunkedBinaryData chunked_changeset(arrays.changesets, offset + i);
            if (chunked_changeset.size() > 0) {
                entry.origin_file_ident = file_ident_type(origin_file_ident);
                entry.remote_version = last_integrated_server_version;
                entry.origin_timestamp = sync::timestamp_type(arrays.origin_timestamps.get(offset + i));
                entry.changeset = chunked_changeset;
                return begin_version + i + 1;
            }
        }
    }
    return 0;
}

// sum_of_history_entry_sizes calculates the sum of the changeset sizes of the
// local history entries that produced a version that succeeds `begin_version`
// and precedes `end_version`.
std::uint_fast64_t ClientHistoryImpl::sum_of_history_entry_sizes(version_type begin_version,
                                                                 version_type end_version) const noexcept
{
    if (begin_version >= end_version)
        return 0;

    REALM_ASSERT(m_arrays->changesets.is_attached());
    REALM_ASSERT(m_arrays->origin_file_idents.is_attached());
    REALM_ASSERT(end_version <= m_sync_history_base_version + sync_history_size());

    version_type begin_version_2 = begin_version;
    version_type end_version_2 = end_version;
    clamp_sync_version_range(begin_version_2, end_version_2);

    std::uint_fast64_t sum_of_sizes = 0;

    std::size_t n = to_size_t(end_version_2 - begin_version_2);
    std::size_t offset = to_size_t(begin_version_2 - m_sync_history_base_version);
    for (std::size_t i = 0; i < n; ++i) {

        // Only local changesets are considered
        if (m_arrays->origin_file_idents.get(offset + i) != 0)
            continue;

        ChunkedBinaryData changeset(m_arrays->changesets, offset + i);
        sum_of_sizes += changeset.size();
    }

    return sum_of_sizes;
}

void ClientHistoryImpl::prepare_for_write()
{
    if (m_arrays) {
        REALM_ASSERT(m_arrays->root.size() == s_root_size);
        return;
    }

    m_arrays.emplace(*m_db, *m_group);
}


void ClientHistoryImpl::add_ct_history_entry(BinaryData changeset)
{
    // FIXME: BinaryColumn::set() currently interprets BinaryData(0,0) as
    // null. It should probably be changed such that BinaryData(0,0) is always
    // interpreted as the empty string. For the purpose of setting null values,
    // BinaryColumn::set() should accept values of type Optional<BinaryData>().
    if (changeset.is_null())
        changeset = BinaryData("", 0);
    m_arrays->ct_history.add(changeset); // Throws
}


void ClientHistoryImpl::add_sync_history_entry(HistoryEntry entry)
{
    REALM_ASSERT(m_arrays->reciprocal_transforms.size() == sync_history_size());
    REALM_ASSERT(m_arrays->remote_versions.size() == sync_history_size());
    REALM_ASSERT(m_arrays->origin_file_idents.size() == sync_history_size());
    REALM_ASSERT(m_arrays->origin_timestamps.size() == sync_history_size());

    // FIXME: BinaryColumn::set() currently interprets BinaryData(0,0) as
    // null. It should probably be changed such that BinaryData(0,0) is always
    // interpreted as the empty string. For the purpose of setting null values,
    // BinaryColumn::set() should accept values of type Optional<BinaryData>().
    BinaryData changeset_2("", 0);
    if (!entry.changeset.is_null()) {
        changeset_2 = entry.changeset.get_first_chunk();
    }
    m_arrays->changesets.add(changeset_2); // Throws

    {
        // inserts null
        m_arrays->reciprocal_transforms.add(BinaryData{}); // Throws
    }
    m_arrays->remote_versions.insert(realm::npos, std::int_fast64_t(entry.remote_version));       // Throws
    m_arrays->origin_file_idents.insert(realm::npos, std::int_fast64_t(entry.origin_file_ident)); // Throws
    m_arrays->origin_timestamps.insert(realm::npos, std::int_fast64_t(entry.origin_timestamp));   // Throws
}


void ClientHistoryImpl::update_sync_progress(const SyncProgress& progress,
                                             const std::uint_fast64_t* downloadable_bytes)
{
    Array& root = m_arrays->root;

    // Progress must never decrease
    REALM_ASSERT(progress.latest_server_version.version >=
                 version_type(root.get_as_ref_or_tagged(s_progress_latest_server_version_iip).get_as_int()));
    REALM_ASSERT(progress.download.server_version >=
                 version_type(root.get_as_ref_or_tagged(s_progress_download_server_version_iip).get_as_int()));
    REALM_ASSERT(progress.download.last_integrated_client_version >=
                 version_type(root.get_as_ref_or_tagged(s_progress_download_client_version_iip).get_as_int()));
    REALM_ASSERT(progress.upload.client_version >=
                 version_type(root.get_as_ref_or_tagged(s_progress_upload_client_version_iip).get_as_int()));
    if (progress.upload.last_integrated_server_version > 0) {
        REALM_ASSERT(progress.upload.last_integrated_server_version >=
                     version_type(root.get_as_ref_or_tagged(s_progress_upload_server_version_iip).get_as_int()));
    }

    auto uploaded_bytes = std::uint_fast64_t(root.get_as_ref_or_tagged(s_progress_uploaded_bytes_iip).get_as_int());
    auto previous_upload_client_version =
        version_type(root.get_as_ref_or_tagged(s_progress_upload_client_version_iip).get_as_int());
    uploaded_bytes += sum_of_history_entry_sizes(previous_upload_client_version, progress.upload.client_version);

    root.set(s_progress_download_server_version_iip,
             RefOrTagged::make_tagged(progress.download.server_version)); // Throws
    root.set(s_progress_download_client_version_iip,
             RefOrTagged::make_tagged(progress.download.last_integrated_client_version)); // Throws
    root.set(s_progress_latest_server_version_iip,
             RefOrTagged::make_tagged(progress.latest_server_version.version)); // Throws
    root.set(s_progress_latest_server_version_salt_iip,
             RefOrTagged::make_tagged(progress.latest_server_version.salt)); // Throws
    root.set(s_progress_upload_client_version_iip,
             RefOrTagged::make_tagged(progress.upload.client_version)); // Throws
    if (progress.upload.last_integrated_server_version > 0) {
        root.set(s_progress_upload_server_version_iip,
                 RefOrTagged::make_tagged(progress.upload.last_integrated_server_version)); // Throws
    }
    if (downloadable_bytes) {
        root.set(s_progress_downloadable_bytes_iip,
                 RefOrTagged::make_tagged(*downloadable_bytes)); // Throws
    }
    root.set(s_progress_uploaded_bytes_iip,
             RefOrTagged::make_tagged(uploaded_bytes)); // Throws

    m_progress_download = progress.download;

    trim_sync_history(); // Throws
}


void ClientHistoryImpl::trim_ct_history()
{
    version_type begin = m_ct_history_base_version;
    version_type end = m_version_of_oldest_bound_snapshot;

    // Because `m_version_of_oldest_bound_snapshot` in this history object is
    // only updated by those transactions that occur on behalf of SharedGroup
    // object that is associated with this history object, it can happen that
    // `m_version_of_oldest_bound_snapshot` precedes the beginning of the
    // history, even though that seems nonsensical. In such a case, no trimming
    // can be done yet.
    if (end > begin) {
        std::size_t n = std::size_t(end - begin);

        // The new changeset is always added before set_oldest_bound_version()
        // is called. Therefore, the trimming operation can never leave the
        // history empty.
        REALM_ASSERT(n < ct_history_size());

        for (std::size_t i = 0; i < n; ++i) {
            std::size_t j = (n - 1) - i;
            m_arrays->ct_history.erase(j);
        }

        m_ct_history_base_version += n;

        REALM_ASSERT(m_ct_history_base_version + ct_history_size() ==
                     m_sync_history_base_version + sync_history_size());
    }
}


// Trimming rules for synchronization history:
//
// Let C be the latest client version that was integrated on the server prior to
// the latest server version currently integrated by the client
// (`m_progress_download.last_integrated_client_version`).
//
// Definition: An *upload skippable history entry* is one whose changeset is
// either empty, or of remote origin.
//
// Then, a history entry, E, can be trimmed away if it preceeds C, or E is
// upload skippable, and there are no upload nonskippable entries between C and
// E.
//
// Since the history representation is contiguous, it is necessary that the
// trimming rule upholds the following invariant:
//
// > If a changeset can be trimmed, then any earlier changeset can also be
// > trimmed.
//
// Note that C corresponds to the earliest possible beginning of the merge
// window for the next incoming changeset from the server.
void ClientHistoryImpl::trim_sync_history()
{
    version_type begin = m_sync_history_base_version;
    version_type end = std::max(m_progress_download.last_integrated_client_version, s_initial_version + 0);
    // Note: At this point, `end` corresponds to C in the description above.

    // `end` (`m_progress_download.last_integrated_client_version`) will precede
    // the beginning of the history, if we trimmed beyond
    // `m_progress_download.last_integrated_client_version` during the previous
    // trimming session. Since new entries, that have now become eligible for
    // scanning, may also be upload skippable, we need to continue the scan from
    // the beginning of the history in that case.
    if (end < begin)
        end = begin;

    // FIXME: It seems like in some cases, a particular history entry that
    // terminates the scan may get examined over and over every time
    // trim_history() is called. For this reason, it seems like it would be
    // worth considering to cache the outcome.

    // FIXME: It seems like there is a significant overlap between what is going
    // on here and in a place like find_uploadable_changesets(). Maybe there is
    // grounds for some refactoring to take that into account, especially, to
    // avoid scanning the same parts of the history for the same information
    // multiple times.

    {
        std::size_t offset = std::size_t(end - begin);
        std::size_t n = std::size_t(sync_history_size() - offset);
        std::size_t i = 0;
        while (i < n) {
            std::int_fast64_t origin_file_ident = m_arrays->origin_file_idents.get(offset + i);
            bool of_local_origin = (origin_file_ident == 0);
            if (of_local_origin) {
                std::size_t pos = 0;
                BinaryData chunk = m_arrays->changesets.get_at(offset + i, pos);
                bool nonempty = (chunk.size() > 0);
                if (nonempty)
                    break; // Not upload skippable
            }
            ++i;
        }
        end += i;
    }

    std::size_t n = std::size_t(end - begin);
    do_trim_sync_history(n); // Throws
}

bool ClientHistoryImpl::no_pending_local_changes(version_type version) const
{
    ensure_updated(version);
    for (size_t i = 0; i < sync_history_size(); i++) {
        if (m_arrays->origin_file_idents.get(i) == 0) {
            std::size_t pos = 0;
            BinaryData chunk = m_arrays->changesets.get_at(i, pos);
            if (chunk.size() > 0)
                return false;
        }
    }
    return true;
}

void ClientHistoryImpl::do_trim_sync_history(std::size_t n)
{
    REALM_ASSERT(sync_history_size() == sync_history_size());
    REALM_ASSERT(m_arrays->reciprocal_transforms.size() == sync_history_size());
    REALM_ASSERT(m_arrays->remote_versions.size() == sync_history_size());
    REALM_ASSERT(m_arrays->origin_file_idents.size() == sync_history_size());
    REALM_ASSERT(m_arrays->origin_timestamps.size() == sync_history_size());
    REALM_ASSERT(n <= sync_history_size());

    if (n > 0) {
        // FIXME: shouldn't this be using truncate()?
        for (std::size_t i = 0; i < n; ++i) {
            std::size_t j = (n - 1) - i;
            m_arrays->changesets.erase(j); // Throws
        }
        for (std::size_t i = 0; i < n; ++i) {
            std::size_t j = (n - 1) - i;
            m_arrays->reciprocal_transforms.erase(j); // Throws
        }
        for (std::size_t i = 0; i < n; ++i) {
            std::size_t j = (n - 1) - i;
            m_arrays->remote_versions.erase(j); // Throws
        }
        for (std::size_t i = 0; i < n; ++i) {
            std::size_t j = (n - 1) - i;
            m_arrays->origin_file_idents.erase(j); // Throws
        }
        for (std::size_t i = 0; i < n; ++i) {
            std::size_t j = (n - 1) - i;
            m_arrays->origin_timestamps.erase(j); // Throws
        }

        m_sync_history_base_version += n;
    }
}

void ClientHistoryImpl::fix_up_client_file_ident_in_stored_changesets(Transaction& group,
                                                                      file_ident_type client_file_ident)
{
    // Must be in write transaction!

    REALM_ASSERT(client_file_ident != 0);
    using Instruction = realm::sync::Instruction;
    auto promote_global_key = [client_file_ident](GlobalKey* oid) {
        if (oid->hi() == 0) {
            // client_file_ident == 0
            *oid = GlobalKey{uint64_t(client_file_ident), oid->lo()};
            return true;
        }
        return false;
    };

    auto get_table_for_class = [&](StringData class_name) -> ConstTableRef {
        REALM_ASSERT(class_name.size() < Group::max_table_name_length - 6);
        sync::TableNameBuffer buffer;
        return group.get_table(sync::class_name_to_table_name(class_name, buffer));
    };

    // Fix up changesets.
    Array& root = m_arrays->root;
    uint64_t uploadable_bytes = root.get_as_ref_or_tagged(s_progress_uploadable_bytes_iip).get_as_int();
    for (size_t i = 0; i < sync_history_size(); ++i) {
        // We could have opened a pre-provisioned realm file. In this case we can skip the entries downloaded
        // from the server.
        if (m_arrays->origin_file_idents.get(i) != 0)
            continue;

        // FIXME: We have to do this when transmitting/receiving changesets
        // over the network instead.
        ChunkedBinaryData changeset{m_arrays->changesets, i};
        ChunkedBinaryInputStream in{changeset};
        sync::Changeset log;
        sync::parse_changeset(in, log);

        size_t size_before = changeset.size();
        bool did_modify = false;
        auto last_class_name = sync::InternString::npos;
        ConstTableRef selected_table;
        for (auto instr : log) {
            if (!instr)
                continue;

            if (auto obj_instr = instr->get_if<Instruction::ObjectInstruction>()) {
                // Cache the TableRef
                if (obj_instr->table != last_class_name) {
                    StringData class_name = log.get_string(obj_instr->table);
                    last_class_name = obj_instr->table;
                    selected_table = get_table_for_class(class_name);
                }

                // Fix up instructions using GlobalKey to identify objects.
                if (auto global_key = mpark::get_if<GlobalKey>(&obj_instr->object)) {
                    did_modify = promote_global_key(global_key);
                }

                // Fix up the payload for Set and ArrayInsert.
                Instruction::Payload* payload = nullptr;
                if (auto set_instr = instr->get_if<Instruction::Update>()) {
                    payload = &set_instr->value;
                }
                else if (auto list_insert_instr = instr->get_if<Instruction::ArrayInsert>()) {
                    payload = &list_insert_instr->value;
                }

                if (payload && payload->type == Instruction::Payload::Type::Link) {
                    if (auto global_key = mpark::get_if<GlobalKey>(&payload->data.link.target)) {
                        did_modify = promote_global_key(global_key);
                    }
                }
            }
        }

        if (did_modify) {
            util::AppendBuffer<char> modified;
            encode_changeset(log, modified);
            BinaryData result = BinaryData{modified.data(), modified.size()};
            m_arrays->changesets.set(i, result);
            uploadable_bytes += (modified.size() - size_before);
        }
    }

    root.set(s_progress_uploadable_bytes_iip, RefOrTagged::make_tagged(uploadable_bytes));
}

// Overriding member function in realm::sync::ClientHistory
void ClientHistoryImpl::set_group(Group* group, bool updated)
{
    _impl::History::set_group(group, updated);
    if (m_arrays)
        _impl::GroupFriend::set_history_parent(*m_group, m_arrays->root);
}

void ClientHistoryImpl::record_current_schema_version()
{
    using gf = _impl::GroupFriend;
    Allocator& alloc = gf::get_alloc(*m_group);
    auto ref = gf::get_history_ref(*m_group);
    REALM_ASSERT(ref != 0);
    Array root{alloc};
    gf::set_history_parent(*m_group, root);
    root.init_from_ref(ref);
    Array schema_versions{alloc};
    schema_versions.set_parent(&root, s_schema_versions_iip);
    schema_versions.init_from_parent();
    version_type snapshot_version = m_db->get_version_of_latest_snapshot();
    record_current_schema_version(schema_versions, snapshot_version); // Throws
}


void ClientHistoryImpl::record_current_schema_version(Array& schema_versions, version_type snapshot_version)
{
    static_assert(s_schema_versions_size == 4, "");
    REALM_ASSERT(schema_versions.size() == s_schema_versions_size);

    Allocator& alloc = schema_versions.get_alloc();
    {
        Array sv_schema_versions{alloc};
        sv_schema_versions.set_parent(&schema_versions, s_sv_schema_versions_iip);
        sv_schema_versions.init_from_parent();
        int schema_version = get_client_history_schema_version();
        sv_schema_versions.add(schema_version); // Throws
    }
    {
        Array sv_library_versions{alloc};
        sv_library_versions.set_parent(&schema_versions, s_sv_library_versions_iip);
        sv_library_versions.init_from_parent();
        const char* library_version = REALM_VERSION_STRING;
        std::size_t size = std::strlen(library_version);
        Array value{alloc};
        bool context_flag = false;
        value.create(Array::type_Normal, context_flag, size); // Throws
        _impl::ShallowArrayDestroyGuard adg{&value};
        using uchar = unsigned char;
        for (std::size_t i = 0; i < size; ++i)
            value.set(i, std::int_fast64_t(uchar(library_version[i]))); // Throws
        sv_library_versions.add(std::int_fast64_t(value.get_ref()));    // Throws
        adg.release();                                                  // Ownership transferred to parent array
    }
    {
        Array sv_snapshot_versions{alloc};
        sv_snapshot_versions.set_parent(&schema_versions, s_sv_snapshot_versions_iip);
        sv_snapshot_versions.init_from_parent();
        sv_snapshot_versions.add(std::int_fast64_t(snapshot_version)); // Throws
    }
    {
        Array sv_timestamps{alloc};
        sv_timestamps.set_parent(&schema_versions, s_sv_timestamps_iip);
        sv_timestamps.init_from_parent();
        std::time_t timestamp = std::time(nullptr);
        sv_timestamps.add(std::int_fast64_t(timestamp)); // Throws
    }
}

// Overriding member function in realm::_impl::History
void ClientHistoryImpl::update_from_ref_and_version(ref_type ref, version_type version)
{
    if (ref == 0) {
        // No history
        m_ct_history_base_version = version;
        m_sync_history_base_version = version;
        m_arrays.reset();
        m_progress_download = {0, 0};
        return;
    }
    if (REALM_LIKELY(m_arrays)) {
        m_arrays->init_from_ref(ref);
    }
    else {
        m_arrays.emplace(m_db->get_alloc(), *m_group, ref);
    }

    m_ct_history_base_version = version - ct_history_size();
    m_sync_history_base_version = version - sync_history_size();
    REALM_ASSERT(m_arrays->reciprocal_transforms.size() == sync_history_size());
    REALM_ASSERT(m_arrays->remote_versions.size() == sync_history_size());
    REALM_ASSERT(m_arrays->origin_file_idents.size() == sync_history_size());
    REALM_ASSERT(m_arrays->origin_timestamps.size() == sync_history_size());

    const Array& root = m_arrays->root;
    m_progress_download.server_version =
        version_type(root.get_as_ref_or_tagged(s_progress_download_server_version_iip).get_as_int());
    m_progress_download.last_integrated_client_version =
        version_type(root.get_as_ref_or_tagged(s_progress_download_client_version_iip).get_as_int());
}


// Overriding member function in realm::_impl::History
void ClientHistoryImpl::update_from_parent(version_type current_version)
{
    using gf = GroupFriend;
    ref_type ref = gf::get_history_ref(*m_group);
    update_from_ref_and_version(ref, current_version); // Throws
}


// Overriding member function in realm::_impl::History
void ClientHistoryImpl::get_changesets(version_type begin_version, version_type end_version,
                                       BinaryIterator* iterators) const noexcept
{
    REALM_ASSERT(begin_version <= end_version);
    REALM_ASSERT(begin_version >= m_ct_history_base_version);
    REALM_ASSERT(end_version <= m_ct_history_base_version + ct_history_size());
    std::size_t n = to_size_t(end_version - begin_version);
    REALM_ASSERT(n == 0 || m_arrays);
    std::size_t offset = to_size_t(begin_version - m_ct_history_base_version);
    for (std::size_t i = 0; i < n; ++i)
        iterators[i] = BinaryIterator(&m_arrays->ct_history, offset + i);
}


// Overriding member function in realm::_impl::History
void ClientHistoryImpl::set_oldest_bound_version(version_type version)
{
    REALM_ASSERT(version >= m_version_of_oldest_bound_snapshot);
    if (version > m_version_of_oldest_bound_snapshot) {
        m_version_of_oldest_bound_snapshot = version;
        trim_ct_history(); // Throws
    }
}

// Overriding member function in realm::_impl::History
BinaryData ClientHistoryImpl::get_uncommitted_changes() const noexcept
{
    return TrivialReplication::get_uncommitted_changes();
}

// Overriding member function in realm::_impl::History
void ClientHistoryImpl::verify() const
{
#ifdef REALM_DEBUG
    // The size of the continuous transactions history can only be zero when the
    // Realm is in the initial empty state where top-ref is null.
    REALM_ASSERT(ct_history_size() != 0 || m_ct_history_base_version == s_initial_version + 0);

    if (!m_arrays) {
        REALM_ASSERT(m_progress_download.server_version == 0);
        REALM_ASSERT(m_progress_download.last_integrated_client_version == 0);
        return;
    }
    m_arrays->verify();

    auto& root = m_arrays->root;
    version_type progress_download_server_version =
        version_type(root.get_as_ref_or_tagged(s_progress_download_server_version_iip).get_as_int());
    version_type progress_download_client_version =
        version_type(root.get_as_ref_or_tagged(s_progress_download_client_version_iip).get_as_int());
    REALM_ASSERT(progress_download_server_version == m_progress_download.server_version);
    REALM_ASSERT(progress_download_client_version == m_progress_download.last_integrated_client_version);
    REALM_ASSERT(progress_download_client_version <= m_sync_history_base_version + sync_history_size());
    version_type remote_version_of_last_entry = 0;
    if (auto size = sync_history_size())
        remote_version_of_last_entry = m_arrays->remote_versions.get(size - 1);
    REALM_ASSERT(progress_download_server_version >= remote_version_of_last_entry);

    // Verify that there is no cooked history.
    Array cooked_history{m_db->get_alloc()};
    cooked_history.set_parent(&root, s_cooked_history_iip);
    REALM_ASSERT(cooked_history.get_ref_from_parent() == 0);
#endif // REALM_DEBUG
}

ClientHistoryImpl::Arrays::Arrays(Allocator& alloc) noexcept
    : root(alloc)
    , ct_history(alloc)
    , changesets(alloc)
    , reciprocal_transforms(alloc)
    , remote_versions(alloc)
    , origin_file_idents(alloc)
    , origin_timestamps(alloc)
{
}

ClientHistoryImpl::Arrays::Arrays(DB& db, Group& group)
    : Arrays(db.get_alloc())
{
    auto& alloc = db.get_alloc();
    {
        bool context_flag = false;
        std::size_t size = s_root_size;
        root.create(Array::type_HasRefs, context_flag, size); // Throws
    }
    DeepArrayDestroyGuard dg{&root};

    ct_history.set_parent(&root, s_ct_history_iip);
    ct_history.create(); // Throws
    changesets.set_parent(&root, s_changesets_iip);
    changesets.create(); // Throws
    reciprocal_transforms.set_parent(&root, s_reciprocal_transforms_iip);
    reciprocal_transforms.create(); // Throws
    remote_versions.set_parent(&root, s_remote_versions_iip);
    remote_versions.create(); // Throws
    origin_file_idents.set_parent(&root, s_origin_file_idents_iip);
    origin_file_idents.create(); // Throws
    origin_timestamps.set_parent(&root, s_origin_timestamps_iip);
    origin_timestamps.create(); // Throws

    { // `schema_versions` table
        Array schema_versions{alloc};
        bool context_flag = false;
        std::size_t size = s_schema_versions_size;
        schema_versions.create(Array::type_HasRefs, context_flag, size); // Throws
        _impl::DeepArrayDestroyGuard adg{&schema_versions};

        auto create_array = [&](NodeHeader::Type type, int ndx_in_parent) {
            MemRef mem = Array::create_empty_array(type, context_flag, alloc);
            ref_type ref = mem.get_ref();
            _impl::DeepArrayRefDestroyGuard ardg{ref, alloc};
            schema_versions.set_as_ref(ndx_in_parent, ref); // Throws
            ardg.release();                                 // Ownership transferred to parent array
        };
        create_array(Array::type_Normal, s_sv_schema_versions_iip);
        create_array(Array::type_HasRefs, s_sv_library_versions_iip);
        create_array(Array::type_Normal, s_sv_snapshot_versions_iip);
        create_array(Array::type_Normal, s_sv_timestamps_iip);

        version_type snapshot_version = db.get_version_of_latest_snapshot();
        record_current_schema_version(schema_versions, snapshot_version);  // Throws
        root.set_as_ref(s_schema_versions_iip, schema_versions.get_ref()); // Throws
        adg.release();                                                     // Ownership transferred to parent array
    }
    _impl::GroupFriend::prepare_history_parent(group, root, Replication::hist_SyncClient,
                                               get_client_history_schema_version(), 0); // Throws
    // Note: gf::prepare_history_parent() also ensures the the root array has a
    // slot for the history ref.
    root.update_parent(); // Throws
    dg.release();
}

ClientHistoryImpl::Arrays::Arrays(Allocator& alloc, Group& parent, ref_type ref)
    : Arrays(alloc)
{
    using gf = _impl::GroupFriend;
    root.init_from_ref(ref);
    gf::set_history_parent(parent, root);

    ct_history.set_parent(&root, s_ct_history_iip);
    changesets.set_parent(&root, s_changesets_iip);
    reciprocal_transforms.set_parent(&root, s_reciprocal_transforms_iip);
    remote_versions.set_parent(&root, s_remote_versions_iip);
    origin_file_idents.set_parent(&root, s_origin_file_idents_iip);
    origin_timestamps.set_parent(&root, s_origin_timestamps_iip);

    init_from_ref(ref); // Throws

    Array cooked_history{alloc};
    cooked_history.set_parent(&root, s_cooked_history_iip);
    // We should have no cooked history in existing Realms.
    REALM_ASSERT(cooked_history.get_ref_from_parent() == 0);
}

void ClientHistoryImpl::Arrays::Arrays::init_from_ref(ref_type ref)
{
    root.init_from_ref(ref);
    REALM_ASSERT(root.size() == s_root_size);
    {
        ref_type ref_2 = root.get_as_ref(s_ct_history_iip);
        ct_history.init_from_ref(ref_2); // Throws
    }
    {
        ref_type ref_2 = root.get_as_ref(s_changesets_iip);
        changesets.init_from_ref(ref_2); // Throws
    }
    {
        ref_type ref_2 = root.get_as_ref(s_reciprocal_transforms_iip);
        reciprocal_transforms.init_from_ref(ref_2); // Throws
    }
    remote_versions.init_from_parent();    // Throws
    origin_file_idents.init_from_parent(); // Throws
    origin_timestamps.init_from_parent();  // Throws
}

void ClientHistoryImpl::Arrays::verify() const
{
#ifdef REALM_DEBUG
    root.verify();
    ct_history.verify();
    changesets.verify();
    reciprocal_transforms.verify();
    remote_versions.verify();
    origin_file_idents.verify();
    origin_timestamps.verify();
    REALM_ASSERT(root.size() == s_root_size);
    REALM_ASSERT(reciprocal_transforms.size() == changesets.size());
    REALM_ASSERT(remote_versions.size() == changesets.size());
    REALM_ASSERT(origin_file_idents.size() == changesets.size());
    REALM_ASSERT(origin_timestamps.size() == changesets.size());
#endif // REALM_DEBUG
}
