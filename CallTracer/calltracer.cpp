#include "calltracer.hpp"

static void event_exit(void);
static void event_thread_init(void *drcontext);
static void event_thread_exit(void *drcontext);
static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data);
void log_file_close(file_t log);
file_t log_file_open(client_id_t id, void *drcontext, const char *path, const char *name,
              uint flags);
				
static int tls_idx;

static client_id_t client_id;

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'CallTracer'", "https://github.com/mimicji/HeapTracer");
    drmgr_init();
    client_id = id;

    dr_register_exit_event(event_exit);
    drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);

    if (drsym_init(0) != DRSYM_SUCCESS) 
	{
		LOG("WARNING: Unable to initialize symbol translation.");
    }

    tls_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx > -1);

	LOG("Start tracing.");
}

static void event_exit(void)
{
    if (drsym_exit() != DRSYM_SUCCESS) 
	{
		LOG("WARNING: Unable to clean up symbol library.");
    }
    drmgr_unregister_tls_field(tls_idx);
    drmgr_exit();
}

static void event_thread_init(void *drcontext)
{
	tls_t *tls_data = (tls_t *)dr_thread_alloc(drcontext, sizeof(tls_t));

    /* We're going to dump our data to a per-thread file.
     * On Windows we need an absolute path so we place it in
     * the same directory as our library. We could also pass
     * in a path as a client argument.
     */
    tls_data->call_trace_file = log_file_open(client_id, drcontext, NULL /* client lib path */, "calltrace",
#ifndef WINDOWS
                      DR_FILE_CLOSE_ON_FORK |
#endif
                          DR_FILE_ALLOW_LARGE);
    tls_data->stack_depth = 0;
    DR_ASSERT(tls_data->call_trace_file != INVALID_FILE);

    /* store it in the slot provided in the drcontext */
    drmgr_set_tls_field(drcontext, tls_idx, (void *)tls_data);
}

static void
event_thread_exit(void *drcontext)
{
    tls_t *tls_data = (tls_t *)drmgr_get_tls_field(drcontext, tls_idx);
    log_file_close(tls_data->call_trace_file);
	dr_thread_free(drcontext, tls_data, sizeof(tls_t));
}

static void print_address(file_t f, app_pc addr, const char *prefix)
{
    drsym_error_t symres;
    drsym_info_t sym;
    char name[MAX_SYM_RESULT];
    char file[MAX_FILE_PATH];
    module_data_t *data;
    data = dr_lookup_module(addr);
    if (data == NULL) {
        dr_fprintf(f, "%s " PFX " ? ??:0\n", prefix, addr);
        return;
    }
    sym.struct_size = sizeof(sym);
    sym.name = name;
    sym.name_size = MAX_SYM_RESULT;
    sym.file = file;
    sym.file_size = MAX_FILE_PATH;
    symres = drsym_lookup_address(data->full_path, addr - data->start, &sym,
                                  DRSYM_DEFAULT_FLAGS);
    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        const char *modname = dr_module_preferred_name(data);
        if (modname == NULL)
            modname = "<noname>";
        dr_fprintf(f, "%s " PFX " %s!%s+" PIFX, prefix, addr, modname, sym.name,
                   addr - data->start - sym.start_offs);
        if (symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
            dr_fprintf(f, " ??:0\n");
        } else {
            dr_fprintf(f, " %s:%" UINT64_FORMAT_CODE "+" PIFX "\n", sym.file, sym.line,
                       sym.line_offs);
        }
    } else
        dr_fprintf(f, "%s " PFX " ? ??:0\n", prefix, addr);
    dr_free_module_data(data);
}

static void
at_call(app_pc instr_addr, app_pc target_addr)
{
    void *drcontext = dr_get_current_drcontext();
    tls_t *tls_data = (tls_t *)drmgr_get_tls_field(drcontext, tls_idx);
    file_t f = tls_data->call_trace_file;
    dr_mcontext_t mc = { sizeof(mc), DR_MC_CONTROL /*only need xsp*/ };
    dr_get_mcontext(drcontext, &mc);
    print_address(f, instr_addr, "CALL @ ");
    print_address(f, target_addr, "\t to ");
    dr_fprintf(f, "\tRSP=" PFX "\n", mc.xsp);
	// dr_fprintf(f, "CALL @ " PFX " to " PFX ", TOS is " PFX "\n", instr_addr, target_addr, mc.xsp);
}

static void at_call_ind(app_pc instr_addr, app_pc target_addr)
{
    void *drcontext = dr_get_current_drcontext();
    tls_t *tls_data = (tls_t *)drmgr_get_tls_field(drcontext, tls_idx);
    file_t f = tls_data->call_trace_file;
    dr_mcontext_t mc = { sizeof(mc), DR_MC_CONTROL /*only need xsp*/ };
    dr_get_mcontext(drcontext, &mc);
	print_address(f, instr_addr, "CALL INDIRECT @ ");
    print_address(f, target_addr, "\t to ");
    dr_fprintf(f, "\tRSP=" PFX "\n", mc.xsp);
    // dr_fprintf(f, "CALL INDIRECT @ " PFX " to " PFX "\n", instr_addr, target_addr);
}

static void
at_return(app_pc instr_addr, app_pc target_addr)
{
    void *drcontext = dr_get_current_drcontext();
    tls_t *tls_data = (tls_t *)drmgr_get_tls_field(drcontext, tls_idx);
    file_t f = tls_data->call_trace_file;
    dr_mcontext_t mc = { sizeof(mc), DR_MC_CONTROL /*only need xsp*/ };
    dr_get_mcontext(drcontext, &mc);
	print_address(f, instr_addr, "RETURN @ ");
    print_address(f, target_addr, "\t to ");
    dr_fprintf(f, "\tRSP=" PFX "\n", mc.xsp);
    // dr_fprintf(f, "RETURN @ " PFX " to " PFX "\n", instr_addr, target_addr);
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
#ifdef VERBOSE
    if (drmgr_is_first_instr(drcontext, instr)) {
        dr_printf("in dr_basic_block(tag=" PFX ")\n", tag);
#    if VERBOSE_VERBOSE
        instrlist_disassemble(drcontext, tag, bb, STDOUT);
#    endif
    }
#endif
    /* instrument calls and returns -- ignore far calls/rets */
    if (instr_is_call_direct(instr)) 
	{
        dr_insert_call_instrumentation(drcontext, bb, instr, (app_pc)at_call);
    } 
	else if (instr_is_call_indirect(instr)) 
	{
        dr_insert_mbr_instrumentation(drcontext, bb, instr, (app_pc)at_call_ind,
                                      SPILL_SLOT_1);
    } 
	else if (instr_is_return(instr)) 
	{
        dr_insert_mbr_instrumentation(drcontext, bb, instr, (app_pc)at_return,
                                      SPILL_SLOT_1);
    }
    return DR_EMIT_DEFAULT;
}

file_t log_file_open(client_id_t id, void *drcontext, const char *path, const char *name,
              uint flags)
{
    file_t log;
    char log_dir[MAXIMUM_PATH];
    char buf[MAXIMUM_PATH];
    size_t len;
    char *dirsep;

    DR_ASSERT(name != NULL);
    len = dr_snprintf(log_dir, BUFFER_SIZE_ELEMENTS(log_dir), "%s",
                      path == NULL ? dr_get_client_path(id) : path);
    DR_ASSERT(len > 0);
    NULL_TERMINATE_BUFFER(log_dir);
    dirsep = log_dir + len - 1;
    if (path == NULL /* removing client lib */ ||
        /* path does not have a trailing / and is too large to add it */
        (*dirsep != '/' IF_WINDOWS(&&*dirsep != '\\') &&
         len == BUFFER_SIZE_ELEMENTS(log_dir) - 1)) {
        for (dirsep = log_dir + len; *dirsep != '/' IF_WINDOWS(&&*dirsep != '\\');
             dirsep--)
            DR_ASSERT(dirsep > log_dir);
    }
    /* remove trailing / if necessary */
    if (*dirsep == '/' IF_WINDOWS(|| *dirsep == '\\'))
        *dirsep = 0;
    else if (sizeof(log_dir) > (dirsep + 1 - log_dir) / sizeof(log_dir[0]))
        *(dirsep + 1) = 0;
    NULL_TERMINATE_BUFFER(log_dir);
    /* we do not need call drx_init before using drx_open_unique_appid_file */
    log = drx_open_unique_appid_file(log_dir, dr_get_process_id(), name, "log", flags,
                                     buf, BUFFER_SIZE_ELEMENTS(buf));
    if (log != INVALID_FILE) {
        char msg[MAXIMUM_PATH];
        len = dr_snprintf(msg, BUFFER_SIZE_ELEMENTS(msg), "Trace file %s created", buf);
        DR_ASSERT(len > 0);
        NULL_TERMINATE_BUFFER(msg);
        dr_log(drcontext, DR_LOG_ALL, 1, "%s", msg);
        LOG("%s", msg);
	}
    return log;
}

void log_file_close(file_t log)
{
    dr_close_file(log);
}