import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const source = readFileSync(new URL("../NacosAdminConsole.vue", import.meta.url), "utf8");

describe("NacosAdminConsole config workbench layout", () => {
  it("keeps the editor as the final and primary workbench surface", () => {
    const contextBar = source.indexOf('class="nacos-config-context-bar');
    const inspector = source.indexOf('class="nacos-config-inspector');
    const toolbar = source.indexOf('class="nacos-editor-toolbar');
    const editor = source.indexOf('ref="configEditorHost"');

    expect(contextBar).toBeGreaterThan(0);
    expect(inspector).toBeGreaterThan(contextBar);
    expect(toolbar).toBeGreaterThan(inspector);
    expect(editor).toBeGreaterThan(toolbar);
  });

  it("uses split-pane container queries instead of viewport breakpoints", () => {
    expect(source).toContain(".nacos-config-workbench {\n  container-type: inline-size;");
    expect(source).toContain("@container (min-width: 960px)");
    expect(source).toContain("@container (max-width: 480px)");
    expect(source.indexOf('class="nacos-editor-actions-secondary')).toBeLessThan(source.indexOf('class="nacos-editor-actions-primary'));
    expect(source).toContain("grid-template-columns: minmax(0, 1fr) auto;");
  });

  it("tracks format and metadata changes as unsaved configuration state", () => {
    expect(source).toContain("configType.value !== originalConfigType.value");
    expect(source).toContain('(selectedConfig.value.appName || "") !== originalConfigMetadata.value.appName');
    expect(source).toContain('(selectedConfig.value.desc || "") !== originalConfigMetadata.value.desc');
    expect(source).toContain('(selectedConfig.value.tags || "") !== originalConfigMetadata.value.tags');
  });

  it("returns a stale batch apply to preview instead of retrying an expired plan", () => {
    const staleBranch = source.indexOf('isNacosErrorCode(error, "stalePreview")');

    expect(staleBranch).toBeGreaterThan(0);
    expect(source.indexOf("batchPreview.value = null;", staleBranch)).toBeGreaterThan(staleBranch);
    expect(source.indexOf("batchTransferRequest.value = null;", staleBranch)).toBeGreaterThan(staleBranch);
    expect(source.indexOf('batchError.value = t("nacos.previewExpired");', staleBranch)).toBeGreaterThan(staleBranch);
  });

  it("keeps service detail and instance loading as independent guarded requests", () => {
    expect(source).toContain("const serviceDetailRequestGuard = createNacosLatestRequestGuard();");
    expect(source).toContain("const instancesRequestGuard = createNacosLatestRequestGuard();");
    expect(source).toContain("await Promise.all([loadServiceDetail(), loadInstances()]);");
  });

  it("keeps instance weight edits as drafts until the explicit save action", () => {
    expect(source).toContain("instanceWeightDrafts.value[instanceIdentity(instance)] = String(value);");
    expect(source).toContain('@click="requestInstanceWeightUpdate(instance)"');
    expect(source).not.toContain('@change="requestInstanceWeightUpdate(instance)"');
  });

  it("tracks instance operations by token so stale requests cannot lock a row forever", () => {
    expect(source).toContain("const updatingInstanceKeys = ref<Record<string, number>>({});");
    expect(source).toContain("const operationToken = beginInstanceOperation(key);");
    expect(source).toContain("clearInstanceOperation(key, operationToken);");
    expect(source).not.toContain('if (updateId === instanceUpdateSequence) updatingInstanceKey.value = "";');
  });

  it("prevents service-management dialogs from closing through outside clicks or Escape", () => {
    expect(source.match(/@pointer-down-outside\.prevent/g)?.length).toBeGreaterThanOrEqual(3);
    expect(source.match(/@interact-outside\.prevent/g)?.length).toBeGreaterThanOrEqual(3);
    expect(source.match(/@escape-key-down\.prevent/g)?.length).toBeGreaterThanOrEqual(3);
  });

  it("renders service details before the independently scrollable instance cards", () => {
    const detail = source.indexOf("nacos.serviceDetails");
    const instanceCards = source.indexOf('v-for="instance in instances"');
    expect(detail).toBeGreaterThan(0);
    expect(instanceCards).toBeGreaterThan(detail);
  });

  it("keeps verbose service details collapsed until the user expands them", () => {
    expect(source).toContain("const serviceDetailExpanded = ref(false);");
  });

  it("reserves the cluster-clear action space so entering a filter cannot reflow the toolbar", () => {
    expect(source).toContain('class="min-w-0 flex-1"');
    expect(source).toContain('class="flex shrink-0 items-center gap-1"');
    expect(source).toContain(':class="{ invisible: !serviceCluster }"');
    expect(source).toContain(':disabled="instancesLoading || !serviceCluster"');
    expect(source).not.toContain('v-if="serviceCluster"\n                  size="sm"');
  });

  it("separates the service header, filtering controls, and management actions", () => {
    expect(source).toContain('<header class="shrink-0 border-b bg-background">');
    expect(source).toContain('class="flex flex-wrap items-center gap-x-4 gap-y-2 border-t bg-muted/30 px-4 py-2"');
    expect(source).toContain('t("nacos.serviceSettings")');
    expect(source).toContain('t("nacos.registerInstance")');
  });
});
