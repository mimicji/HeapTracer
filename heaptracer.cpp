#include "heaptracer.hpp"

static void event_exit(void);
static void event_thread_init(void *drcontext);
static void event_thread_exit(void *drcontext);
static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data);
void log_file_close(file_t log);
file_t log_file_open(client_id_t id, void *drcontext, const char *path, const char *name,
              uint flags);
void print_indentation(file_t f, int64_t depth);
static void module_load_event(void *drcontext, const module_data_t *mod, bool loaded);
static void print_qualified_function_name(file_t f, app_pc pc);
static void wrap_malloc_pre(void *wrapcxt, OUT void **user_data);
static void wrap_malloc_post(void *wrapcxt, void *user_data);
static void wrap_free_pre(void *wrapcxt, OUT void **user_data);
static void wrap_free_post(void *wrapcxt, void *user_data);
static int tls_idx;

static client_id_t client_id;

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'HeapTracer'", "https://github.com/mimicji/HeapTracer");
    drmgr_init();
    drwrap_init();

    client_id = id;

    dr_register_exit_event(event_exit);
    drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);
    drmgr_register_module_load_event(module_load_event);

    if (drsym_init(0) != DRSYM_SUCCESS) 
	{
		LOG("WARNING: Unable to initialize symbol translation.");
    }

    tls_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx > -1);

    // Improve performance
    drwrap_set_global_flags(static_cast<drwrap_global_flags_t>(DRWRAP_NO_FRILLS | DRWRAP_FAST_CLEANCALLS));

	LOG("Start tracing.");
}

static void event_exit(void)
{
    if (drsym_exit() != DRSYM_SUCCESS) 
	{
		LOG("WARNING: Unable to clean up symbol library.");
    }
    drmgr_unregister_tls_field(tls_idx);
    drwrap_exit();
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
    tls_data->heap_trace_file = log_file_open(client_id, drcontext, NULL /* client lib path */, "heaptrace",
#ifndef WINDOWS
                      DR_FILE_CLOSE_ON_FORK |
#endif
                          DR_FILE_ALLOW_LARGE);
    tls_data->stack_depth = 0;
    tls_data->alloc_cnt = 0;
    tls_data->free_cnt = 0;
    DR_ASSERT(tls_data->call_trace_file != INVALID_FILE);

    /* store it in the slot provided in the drcontext */
    drmgr_set_tls_field(drcontext, tls_idx, (void *)tls_data);
}

static void
event_thread_exit(void *drcontext)
{
    tls_t *tls_data = (tls_t *)drmgr_get_tls_field(drcontext, tls_idx);
    log_file_close(tls_data->call_trace_file);
    log_file_close(tls_data->heap_trace_file);
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

    tls_data->stack_depth++;
    print_indentation(f, tls_data->stack_depth);
    print_address(f, instr_addr, "CALL @ ");
    print_indentation(f, tls_data->stack_depth);
    print_address(f, target_addr, "  to ");
    print_indentation(f, tls_data->stack_depth);
    dr_fprintf(f, "  RSP=" PFX "\n", mc.xsp);
	// dr_fprintf(f, "CALL @ " PFX " to " PFX ", TOS is " PFX "\n", instr_addr, target_addr, mc.xsp);
}

static void at_call_ind(app_pc instr_addr, app_pc target_addr)
{
    void *drcontext = dr_get_current_drcontext();
    tls_t *tls_data = (tls_t *)drmgr_get_tls_field(drcontext, tls_idx);
    file_t f = tls_data->call_trace_file;
    dr_mcontext_t mc = { sizeof(mc), DR_MC_CONTROL /*only need xsp*/ };
    dr_get_mcontext(drcontext, &mc);

    tls_data->stack_depth++;
    print_indentation(f, tls_data->stack_depth);
	print_address(f, instr_addr, "CALL INDIRECT @ ");
    print_indentation(f, tls_data->stack_depth);
    print_address(f, target_addr, "  to ");
    print_indentation(f, tls_data->stack_depth);
    dr_fprintf(f, "  RSP=" PFX "\n", mc.xsp);
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
    print_indentation(f, tls_data->stack_depth);
	print_address(f, instr_addr, "RETURN @ ");
    print_indentation(f, tls_data->stack_depth);
    print_address(f, target_addr, "  TO ");
    print_indentation(f, tls_data->stack_depth);
    dr_fprintf(f, "  RSP=" PFX "\n", mc.xsp);
    tls_data->stack_depth--;
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

static void module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
    // Wrap malloc
    app_pc malloc_towrap = (app_pc)dr_get_proc_address(mod->handle, MALLOC_NAME);
    if (malloc_towrap != NULL) 
    {
        bool ok = drwrap_wrap(malloc_towrap, wrap_malloc_pre, wrap_malloc_post);
        if (ok) {
            LOG("<wrapped " MALLOC_NAME " @" PFX "", malloc_towrap);
        } else {
            LOG("<FAILED to wrap " MALLOC_NAME " @" PFX ": already wrapped?", malloc_towrap);
        }
    }

    // Wrap free
    app_pc free_towrap = (app_pc)dr_get_proc_address(mod->handle, FREE_NAME);
    if (free_towrap != NULL) 
    {
        bool ok = drwrap_wrap(free_towrap, wrap_free_pre, wrap_free_post);
        if (ok) {
            LOG("<wrapped " FREE_NAME " @" PFX "", free_towrap);
        } else {
            LOG("<FAILED to wrap " FREE_NAME " @" PFX ": already wrapped?", free_towrap);
        }
    }
}

static void print_qualified_function_name(file_t f, app_pc pc)
{
    module_data_t *mod = dr_lookup_module(pc);
    if (mod == NULL) {
        // If we end up in assembly code or generated code we'll likely never
        // get out again without stack scanning or frame pointer walking or
        // other strategies not yet part of drcallstack.
        dr_fprintf(f, "  %p@<unknown module>\n", pc);
        return;
    }
    drsym_info_t sym_info;
#define MAX_FUNC_LEN 1024
    char name[MAX_FUNC_LEN];
    char file[MAXIMUM_PATH];
    sym_info.struct_size = sizeof(sym_info);
    sym_info.name = name;
    sym_info.name_size = MAX_FUNC_LEN;
    sym_info.file = file;
    sym_info.file_size = MAXIMUM_PATH;
    const char *func = "<unknown>";
    drsym_error_t sym_res =
        drsym_lookup_address(mod->full_path, pc - mod->start, &sym_info, DRSYM_DEMANGLE);
    if (sym_res == DRSYM_SUCCESS)
    {
        func = sym_info.name;
        dr_fprintf(f, "  %s@%s\n", func, dr_module_preferred_name(mod));
    }
    else
    {
        dr_fprintf(f, "  %p@%s\n", pc, dr_module_preferred_name(mod));
    }

    dr_free_module_data(mod);
}

static void wrap_malloc_pre(void *wrapcxt, OUT void **user_data)
{
    void *drcontext = drwrap_get_drcontext(wrapcxt);
    tls_t *tls_data = (tls_t *)drmgr_get_tls_field(drcontext, tls_idx);
    file_t f = tls_data->heap_trace_file;
    tls_data->alloc_cnt++;
    dr_fprintf(f, "========================================================\n");

    // Find out arguments to malloc
    /* malloc(size) or HeapAlloc(heap, flags, size) */
    size_t sz = (size_t)drwrap_get_arg(wrapcxt, IF_WINDOWS_ELSE(2, 0));

    dr_mcontext_t *mc = drwrap_get_mcontext(wrapcxt);
    // Walk the callstack.
    drcallstack_walk_t *walk;
    drcallstack_status_t res = drcallstack_init_walk(mc, &walk);
    DR_ASSERT(res == DRCALLSTACK_SUCCESS);
    drcallstack_frame_t frame = {
        sizeof(frame),
    };
    int count = 0;
    dr_fprintf(f, "%d: ", count);
    print_qualified_function_name(f, drwrap_get_func(wrapcxt));
    do {
        res = drcallstack_next_frame(walk, &frame);
        if (res != DRCALLSTACK_SUCCESS)
            break;
        ++count;
        dr_fprintf(f, "%d: ", count);
        print_qualified_function_name(f, frame.pc);
    } while (res == DRCALLSTACK_SUCCESS);
    // The return value DRCALLSTACK_NO_MORE_FRAMES indicates a complete callstack.
    // Anything else indicates some kind of unwind info error.
    // If this code were used inside a larger tool it would be up to that tool
    // whether to record or act on the callstack quality.
    res = drcallstack_cleanup_walk(walk);
    DR_ASSERT(res == DRCALLSTACK_SUCCESS);
    
    dr_fprintf(f, "[%llu] %s(0x%llx) = ", tls_data->alloc_cnt, MALLOC_NAME, sz);
}

static void wrap_malloc_post(void *wrapcxt, void *user_data)
{
    void *drcontext = drwrap_get_drcontext(wrapcxt);
    tls_t *tls_data = (tls_t *)drmgr_get_tls_field(drcontext, tls_idx);
    file_t f = tls_data->heap_trace_file;
    dr_fprintf(f, "%p\n", drwrap_get_retval(wrapcxt));   
}

static void wrap_free_pre(void *wrapcxt, OUT void **user_data)
{
    void *drcontext = drwrap_get_drcontext(wrapcxt);
    tls_t *tls_data = (tls_t *)drmgr_get_tls_field(drcontext, tls_idx);
    file_t f = tls_data->heap_trace_file;
    tls_data->free_cnt++;
    dr_fprintf(f, "========================================================\n");

    // Find out arguments to free
    /* free(ptr) or HeapAlloc(heap, flags, ptr) */
    size_t sz = (size_t)drwrap_get_arg(wrapcxt, IF_WINDOWS_ELSE(2, 0));

    dr_mcontext_t *mc = drwrap_get_mcontext(wrapcxt);
    // Walk the callstack.
    drcallstack_walk_t *walk;
    drcallstack_status_t res = drcallstack_init_walk(mc, &walk);
    DR_ASSERT(res == DRCALLSTACK_SUCCESS);
    drcallstack_frame_t frame = {
        sizeof(frame),
    };
    int count = 0;
    dr_fprintf(f, "%d: ", count);
    print_qualified_function_name(f, drwrap_get_func(wrapcxt));
    do {
        res = drcallstack_next_frame(walk, &frame);
        if (res != DRCALLSTACK_SUCCESS)
            break;
        ++count;
        dr_fprintf(f, "%d: ", count);
        print_qualified_function_name(f, frame.pc);
    } while (res == DRCALLSTACK_SUCCESS);
    // The return value DRCALLSTACK_NO_MORE_FRAMES indicates a complete callstack.
    // Anything else indicates some kind of unwind info error.
    // If this code were used inside a larger tool it would be up to that tool
    // whether to record or act on the callstack quality.
    res = drcallstack_cleanup_walk(walk);
    DR_ASSERT(res == DRCALLSTACK_SUCCESS);
    
    dr_fprintf(f, "[%llu] %s(0x%llx)\n", tls_data->free_cnt, FREE_NAME, sz);
}

static void wrap_free_post(void *wrapcxt, void *user_data)
{
    // Nothing to do
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

void print_indentation(file_t f, int64_t depth)
{
    int64_t i;
    DR_ASSERT(depth >=0);
    for (i=1; i<depth; i++)
    {
        dr_fprintf(f, "  ");
    }
}