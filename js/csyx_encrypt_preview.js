import { app } from "../../scripts/app.js";
import { api } from "../../scripts/api.js";
import { requiredNodeHeight, responsiveGridGeometry } from "./csyx_preview_layout.js";

const MANAGED = new Set([
    "CSYX_ImageEncrypt",
    "CSYX_VideoEncrypt",
    "CSYX_AudioEncrypt",
    "CSYX_TextEncrypt",
    "CSYX_FileEncrypt",
]);
const PREVIEW_PROP = "_csyx_encrypt_preview_v2";
const WIDGET_NAME = "csyx_encrypted_preview";
const PREVIEW_NODE_GAP = 8;

function securePasswordWidget(node) {
    const password = node.widgets?.find((item) => item?.name === "密码");
    if (!password) return;
    // Keep the value available to the API prompt, but never persist it in workflow JSON.
    password.serialize = false;
    password.label = "密码（不保存）";
    if (password.inputEl) {
        password.inputEl.type = "password";
        password.inputEl.autocomplete = "new-password";
        password.inputEl.spellcheck = false;
    }
}

function normalizeItems(items) {
    if (!Array.isArray(items)) return [];
    return items.map((item) => {
        if (typeof item === "string") {
            return { filename: item, subfolder: "", type: "output" };
        }
        if (!item || typeof item.filename !== "string") return null;
        return {
            filename: item.filename,
            subfolder: item.subfolder || "",
            type: item.type || "output",
        };
    }).filter(Boolean);
}

function outputItems(message) {
    if (!message) return [];
    const standard = normalizeItems(message.images);
    return standard.length ? standard : normalizeItems(message.csyx_image);
}

function viewUrl(item, lightweight = false) {
    const params = new URLSearchParams({
        filename: item.filename,
        subfolder: item.subfolder || "",
        type: item.type || "output",
    });
    if (lightweight) params.set("preview", "webp;80");
    return api.apiURL(`/view?${params.toString()}`);
}

function downloadFile(item) {
    const anchor = document.createElement("a");
    anchor.href = viewUrl(item, false);
    anchor.download = item.filename;
    anchor.style.display = "none";
    document.body.appendChild(anchor);
    anchor.click();
    setTimeout(() => anchor.remove(), 0);
}

function showNodeContextMenu(node, clientX, clientY) {
    const canvas = app.canvas;
    const canvasElement = canvas?.canvas ?? app.canvasEl;
    if (!canvas?.processContextMenu || !canvasElement) return;
    const rect = canvasElement.getBoundingClientRect();
    const scale = canvas.ds?.scale ?? 1;
    const event = new MouseEvent("contextmenu", {
        clientX,
        clientY,
        button: 2,
        bubbles: true,
        cancelable: true,
    });
    event.canvasX = (clientX - rect.left) / scale - (canvas.ds?.offset?.[0] ?? 0);
    event.canvasY = (clientY - rect.top) / scale - (canvas.ds?.offset?.[1] ?? 0);
    canvas.processContextMenu(node, event);
}

function removeWidget(node) {
    node._csyxPreviewGeneration = (node._csyxPreviewGeneration || 0) + 1;
    if (node._csyxPreviewLayoutFrame != null) {
        globalThis.cancelAnimationFrame?.(node._csyxPreviewLayoutFrame);
        globalThis.clearTimeout?.(node._csyxPreviewLayoutFrame);
        node._csyxPreviewLayoutFrame = null;
    }
    node._csyxPreviewObserver?.disconnect?.();
    node._csyxPreviewObserver = null;
    const widget = node._csyxPreviewWidget;
    if (!widget) return;
    const element = widget.element;
    if (element) {
        element.replaceChildren();
        element.remove();
    }
    const index = node.widgets?.indexOf(widget) ?? -1;
    if (index >= 0) node.widgets.splice(index, 1);
    node._csyxPreviewWidget = null;
    node._csyxPreviewCells = null;
    node._csyxPreviewAspects = null;
    node._csyxPreviewHeight = null;
    node._csyxPendingPreviewWidth = null;
}

function measureBaseNodeHeight(node, previousPreviewHeight = 0) {
    // Measure after the old preview widget has been removed. LiteGraph and
    // Nodes 2.0 use different DOM-widget sizing paths, so retain a safe fallback.
    try {
        const computed = node.computeSize?.();
        if (Array.isArray(computed) && Number.isFinite(Number(computed[1])) && Number(computed[1]) > 0) {
            return Math.max(120, Math.ceil(Number(computed[1])));
        }
    } catch (_) {}
    const currentHeight = Number(node.size?.[1] || 300);
    return Math.max(120, Math.ceil(currentHeight - Math.max(0, previousPreviewHeight) - PREVIEW_NODE_GAP));
}

function suppressNativeNodePreview(node) {
    // ComfyUI 的标准 images 仍保存在执行结果中，只清理节点画布上的原生图片对象。
    if (Array.isArray(node.imgs)) node.imgs.length = 0;
    node.imgs = null;
    node.imageIndex = null;
    node.animatedImages = false;
}

function applyResponsivePreviewLayout(node, widthOverride) {
    const widget = node._csyxPreviewWidget;
    const element = widget?.element;
    const cells = node._csyxPreviewCells || [];
    if (!widget || !element || !cells.length) return null;

    const nodeWidth = Number(widthOverride ?? node.size?.[0] ?? 300);
    const contentWidth = Math.max(160, nodeWidth - 20);
    const geometry = responsiveGridGeometry(cells.length, contentWidth, node._csyxPreviewAspects || []);
    element.style.gridTemplateColumns = `repeat(${geometry.columns},minmax(0,1fr))`;
    element.style.minHeight = "0";
    element.style.height = `${geometry.height}px`;
    for (let index = 0; index < cells.length; index++) {
        const row = Math.floor(index / geometry.columns);
        cells[index].style.height = `${geometry.rowHeights[row]}px`;
    }

    widget.computedHeight = geometry.height;
    node._csyxPreviewHeight = geometry.height;
    widget.computeLayoutSize = () => ({
        minHeight: geometry.height,
        maxHeight: geometry.height,
        minWidth: 200,
    });
    // Both APIs are used in current ComfyUI builds. Supplying all three keeps
    // the DOM allocation and the LiteGraph node size in agreement.
    widget.getMinHeight = () => geometry.height;
    widget.getMaxHeight = () => geometry.height;
    widget.getHeight = () => geometry.height;
    return geometry;
}

function fitNodeToCustomPreview(node, widthOverride) {
    suppressNativeNodePreview(node);
    if (node._csyxPreviewFitting) return;
    node._csyxPreviewFitting = true;
    try {
        const width = Math.max(260, Number(widthOverride ?? node.size?.[0] ?? 300));
        const geometry = applyResponsivePreviewLayout(node, width);
        if (!geometry) return;
        let computedHeight = 0;
        try {
            const computed = node.computeSize?.();
            if (Array.isArray(computed) && Number.isFinite(computed[1])) {
                computedHeight = Math.max(0, Number(computed[1]));
            }
        } catch (_) {}
        computedHeight = Math.max(220, requiredNodeHeight(
            node._csyxPreviewBaseHeight,
            geometry.height,
            computedHeight,
            PREVIEW_NODE_GAP,
        ));
        if (Math.abs(Number(node.size?.[0] || 0) - width) > 0.5
            || Math.abs(Number(node.size?.[1] || 0) - computedHeight) > 0.5) {
            node.setSize?.([width, computedHeight]);
        }
        app.graph?.setDirtyCanvas?.(true, true);
        app.canvas?.setDirty?.(true, true);
    } finally {
        node._csyxPreviewFitting = false;
    }
}

function scheduleResponsivePreviewLayout(node, widthOverride) {
    if (!node._csyxPreviewWidget) return;
    if (Number.isFinite(Number(widthOverride))) node._csyxPendingPreviewWidth = Number(widthOverride);
    if (node._csyxPreviewLayoutFrame != null) return;
    const run = () => {
        node._csyxPreviewLayoutFrame = null;
        const pendingWidth = node._csyxPendingPreviewWidth;
        node._csyxPendingPreviewWidth = null;
        fitNodeToCustomPreview(node, pendingWidth);
    };
    if (typeof requestAnimationFrame === "function") {
        node._csyxPreviewLayoutFrame = requestAnimationFrame(run);
    } else {
        node._csyxPreviewLayoutFrame = setTimeout(run, 0);
    }
}

function scheduleNativePreviewSuppression(node) {
    // 原生预览的图片加载是异步的；分阶段清理，防止稍后再次写回 node.imgs。
    for (const delay of [0, 50, 250, 1000]) {
        setTimeout(() => {
            if (!node._csyxPreviewWidget) return;
            scheduleResponsivePreviewLayout(node);
        }, delay);
    }
}

function createPreviewElement(node, items) {
    const generation = node._csyxPreviewGeneration || 0;
    const root = document.createElement("div");
    root.className = "csyx-encrypted-preview";
    root.style.cssText = [
        "width:100%", "min-height:0", "height:auto", "display:grid",
        "grid-template-columns:repeat(1,minmax(0,1fr))",
        "gap:4px", "align-items:start", "overflow:hidden", "box-sizing:border-box",
        "border-radius:6px", "background:#111",
    ].join(";");

    const cells = [];
    node._csyxPreviewAspects = items.map(() => 1);
    items.forEach((item, index) => {
        const cell = document.createElement("div");
        cell.style.cssText = "position:relative;min-width:0;height:160px;overflow:hidden;background:#111;align-self:start";
        cells.push(cell);

        const image = new Image();
        image.alt = item.filename;
        image.loading = "lazy";
        image.decoding = "async";
        image.style.cssText = "width:100%;height:100%;display:block;object-fit:contain;cursor:pointer";
        image.addEventListener("load", () => {
            if (node._csyxPreviewGeneration !== generation || !node._csyxPreviewAspects) return;
            const aspect = image.naturalWidth / Math.max(1, image.naturalHeight);
            if (Number.isFinite(aspect) && aspect > 0) node._csyxPreviewAspects[index] = aspect;
            scheduleResponsivePreviewLayout(node);
        }, { once: true });
        image.addEventListener("click", () => window.open(viewUrl(item, false), "_blank", "noopener"));
        image.addEventListener("contextmenu", (event) => {
            event.preventDefault();
            event.stopPropagation();
            showNodeContextMenu(node, event.clientX, event.clientY);
        });
        image.addEventListener("error", () => {
            if (node._csyxPreviewGeneration !== generation) return;
            image.remove();
            const error = document.createElement("button");
            error.type = "button";
            error.textContent = `预览加载失败，点击下载\n${item.filename}`;
            error.style.cssText = "width:100%;height:100%;white-space:pre-wrap;color:#ffd36a;background:#241f15;border:0;cursor:pointer";
            error.addEventListener("click", () => downloadFile(item));
            cell.appendChild(error);
        }, { once: true });
        image.src = viewUrl(item, true);
        cell.appendChild(image);

        const label = document.createElement("div");
        label.textContent = item.filename;
        label.title = "左键打开完整文件；右键打开操作菜单";
        label.style.cssText = "position:absolute;left:0;right:0;bottom:0;padding:4px 6px;background:#000b;color:#fff;font:11px sans-serif;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;pointer-events:none";
        cell.appendChild(label);
        root.appendChild(cell);
    });

    node._csyxPreviewCells = cells;

    return root;
}

function showPreview(node, rawItems) {
    const items = normalizeItems(rawItems);
    if (!items.length) return;
    node.properties = node.properties || {};
    node.properties[PREVIEW_PROP] = items;
    const previousPreviewHeight = Number(
        node._csyxPreviewHeight || node._csyxPreviewWidget?.computedHeight || 0,
    );
    removeWidget(node);
    node._csyxPreviewBaseHeight = measureBaseNodeHeight(node, previousPreviewHeight);
    suppressNativeNodePreview(node);

    const element = createPreviewElement(node, items);
    const widget = node.addDOMWidget(WIDGET_NAME, "custom", element, {
        getValue() { return ""; },
        setValue() {},
        serialize: false,
        getMinHeight() { return Number(node._csyxPreviewHeight || 180); },
        getMaxHeight() { return Number(node._csyxPreviewHeight || 180); },
        getHeight() { return Number(node._csyxPreviewHeight || 180); },
    });
    widget.computedHeight = 180;
    widget.computeSize = (width) => {
        const geometry = responsiveGridGeometry(
            items.length,
            Math.max(160, Number(width || node.size?.[0] || 300) - 20),
            node._csyxPreviewAspects || [],
        );
        return [Math.max(260, width || 300), geometry.height];
    };
    node._csyxPreviewWidget = widget;

    applyResponsivePreviewLayout(node);
    if (typeof ResizeObserver === "function") {
        let observedWidth = 0;
        node._csyxPreviewObserver = new ResizeObserver((entries) => {
            const width = Number(entries?.[0]?.contentRect?.width || 0);
            if (!(width > 0) || Math.abs(width - observedWidth) < 1) return;
            observedWidth = width;
            scheduleResponsivePreviewLayout(node, width + 20);
        });
        node._csyxPreviewObserver.observe(element);
    }
    scheduleResponsivePreviewLayout(node);
    scheduleNativePreviewSuppression(node);
}

app.registerExtension({
    name: "CSYX.EncryptPreviewV2",

    async beforeRegisterNodeDef(nodeType, nodeData) {
        if (!MANAGED.has(nodeData.name)) return;

        const originalCreated = nodeType.prototype.onNodeCreated;
        nodeType.prototype.onNodeCreated = function () {
            const result = originalCreated?.apply(this, arguments);
            this.properties = this.properties || {};
            securePasswordWidget(this);
            return result;
        };

        const originalExecuted = nodeType.prototype.onExecuted;
        nodeType.prototype.onExecuted = function (message) {
            // 标准 images 留给历史、底部结果和资产系统；节点画布只加载轻量缩略图。
            if (originalExecuted) {
                const messageWithoutFullNodePreview = { ...message, images: [] };
                originalExecuted.call(this, messageWithoutFullNodePreview);
            }
            const items = outputItems(message);
            if (items.length) showPreview(this, items);
        };

        const originalConfigured = nodeType.prototype.onConfigure;
        nodeType.prototype.onConfigure = function (info) {
            const result = originalConfigured?.apply(this, arguments);
            securePasswordWidget(this);
            const items = normalizeItems(this.properties?.[PREVIEW_PROP]);
            if (items.length) setTimeout(() => showPreview(this, items), 0);
            return result;
        };

        const originalDrawBackground = nodeType.prototype.onDrawBackground;
        nodeType.prototype.onDrawBackground = function () {
            if (this._csyxPreviewWidget) suppressNativeNodePreview(this);
            return originalDrawBackground?.apply(this, arguments);
        };

        const originalResize = nodeType.prototype.onResize;
        nodeType.prototype.onResize = function (size) {
            const result = originalResize?.apply(this, arguments);
            if (this._csyxPreviewWidget && !this._csyxPreviewFitting) {
                scheduleResponsivePreviewLayout(this, Array.isArray(size) ? size[0] : this.size?.[0]);
            }
            return result;
        };

        const originalRemoved = nodeType.prototype.onRemoved;
        nodeType.prototype.onRemoved = function () {
            removeWidget(this);
            return originalRemoved?.apply(this, arguments);
        };

        const originalMenu = nodeType.prototype.getExtraMenuOptions;
        nodeType.prototype.getExtraMenuOptions = function (_, options) {
            const result = originalMenu?.apply(this, arguments);
            const items = normalizeItems(this.properties?.[PREVIEW_PROP]);
            if (items.length) {
                if (options.length && options[options.length - 1] !== null) options.push(null);
                for (const item of items) {
                    options.push({
                        content: `保存完整加密文件：${item.filename}`,
                        callback: () => downloadFile(item),
                    });
                }
            }
            return result;
        };
    },
});
