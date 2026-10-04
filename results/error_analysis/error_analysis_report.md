# Empirical Error Analysis Report

## Summary Metrics
- **Evaluated Samples:** 300
- **True Positives (TP):** 155
- **True Negatives (TN):** 0
- **False Positives (FP):** 145
- **False Negatives (FN):** 0

## High-Confidence False Positives (Actual: SAFE, Model: VULNERABLE)

### False Positive #1
- **Sample ID:** `diversevul_019912`
- **Project:** `xserver` | **CWE:** `CWE-189`
- **Model Confidence:** `0.9999` (Probability: `0.9999`)
- **Code Length:** `27` lines (`20-50`)
```c
ProcShmQueryVersion(client)
    register ClientPtr client;
{
    xShmQueryVersionReply rep;
    register int n;

    REQUEST_SIZE_MATCH(xShmQueryVersionReq);
    rep.type = X_Reply;
    rep.length = 0
```

### False Positive #2
- **Sample ID:** `diversevul_020211`
- **Project:** `m4` | **CWE:** `NVD-CWE-Other`
- **Model Confidence:** `0.9999` (Probability: `0.9999`)
- **Code Length:** `22` lines (`20-50`)
```c
m4_syscmd (struct obstack *obs, int argc, token_data **argv)
{
  if (bad_argc (argv[0], argc, 2, 2))
    {
      /* The empty command is successful.  */
      sysval = 0;
      return;
    }

  debug_
```

### False Positive #3
- **Sample ID:** `diversevul_019632`
- **Project:** `jasper` | **CWE:** `NVD-CWE-Other`
- **Model Confidence:** `0.9999` (Probability: `0.9999`)
- **Code Length:** `11` lines (`<20`)
```c
static int jpc_unk_putparms(jpc_ms_t *ms, jpc_cstate_t *cstate, jas_stream_t *out)
{
	/* Eliminate compiler warning about unused variables. */
	cstate = 0;
	ms = 0;
	out = 0;

	/* If this function is
```

### False Positive #4
- **Sample ID:** `diversevul_018975`
- **Project:** `php-src` | **CWE:** `CWE-264`
- **Model Confidence:** `0.9999` (Probability: `0.9999`)
- **Code Length:** `8` lines (`<20`)
```c
static void php_sqlite3_func_step_callback(sqlite3_context *context, int argc,
	sqlite3_value **argv)
{
	struct pdo_sqlite_func *func = (struct pdo_sqlite_func*)sqlite3_user_data(context);
	TSRMLS_FET
```

### False Positive #5
- **Sample ID:** `diversevul_020214`
- **Project:** `m4` | **CWE:** `NVD-CWE-Other`
- **Model Confidence:** `0.9999` (Probability: `0.9999`)
- **Code Length:** `40` lines (`20-50`)
```c
define_macro (int argc, token_data **argv, symbol_lookup mode)
{
  const builtin *bp;

  if (bad_argc (argv[0], argc, 2, 3))
    return;

  if (TOKEN_DATA_TYPE (argv[1]) != TOKEN_TEXT)
    {
      M4E
```

## High-Confidence False Negatives (Actual: VULNERABLE, Model: SAFE)

No False Negatives observed.
## Error Distribution by CWE
### Top CWEs in False Positives:
- `NVD-CWE-Other`: 104
- `CWE-189`: 20
- `CWE-264`: 18
- `NVD-CWE-noinfo`: 3

### Top CWEs in False Negatives:

## Error Distribution by Function Length
| Length Bin | False Positives | False Negatives |
|---|---|---|
| 20-50 | 40 | 0 |
| 50-100 | 12 | 0 |
| <20 | 88 | 0 |
| >100 | 5 | 0 |