import { app } from "../../scripts/app.js";
import { api } from "../../scripts/api.js";

const MANAGED = ["CSYX_ImageEncrypt", "CSYX_VideoEncrypt", "CSYX_AudioEncrypt", "CSYX_TextEncrypt", "CSYX_FileEncrypt"];
const CW = ["csyx_iw"];

function vu(i) {
    return api.apiURL(`/view?filename=${encodeURIComponent(i.filename)}&subfolder=${encodeURIComponent(i.subfolder||"")}&type=${encodeURIComponent(i.type||"output")}`);
}

function downloadFile(url, filename) {
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
}

function forwardWheelToCanvas(e) {
    const canvasEl = app.canvas?.canvas ?? app.canvasEl;
    if (!canvasEl) return;
    const rect = canvasEl.getBoundingClientRect();
    const fakeEvent = new WheelEvent("wheel", {
        deltaX: e.deltaX, deltaY: e.deltaY, deltaZ: e.deltaZ,
        deltaMode: e.deltaMode,
        clientX: e.clientX, clientY: e.clientY,
        bubbles: false, cancelable: true,
    });
    fakeEvent.canvasX = (e.clientX - rect.left) / (app.canvas?.ds?.scale ?? 1) - (app.canvas?.ds?.offset?.[0] ?? 0);
    fakeEvent.canvasY = (e.clientY - rect.top) / (app.canvas?.ds?.scale ?? 1) - (app.canvas?.ds?.offset?.[1] ?? 0);
    canvasEl.dispatchEvent(fakeEvent);
}

function showNodeContextMenu(node, clientX, clientY) {
    const canvas = app.canvas;
    if (!canvas) return;
    const canvasEl = canvas.canvas ?? app.canvasEl;
    if (!canvasEl) return;
    const rect = canvasEl.getBoundingClientRect();
    const scale = canvas.ds?.scale ?? 1;
    const fakeEvent = new MouseEvent("contextmenu", {
        clientX, clientY,
        button: 2, bubbles: true, cancelable: true,
    });
    fakeEvent.canvasX = (clientX - rect.left) / scale - (canvas.ds?.offset?.[0] ?? 0);
    fakeEvent.canvasY = (clientY - rect.top) / scale - (canvas.ds?.offset?.[1] ?? 0);
    fakeEvent.preventDefault = () => {};
    fakeEvent.stopPropagation = () => {};
    canvas.processContextMenu(node, fakeEvent);
}

app.registerExtension({
    name: "CSYX.EncryptPreview",
    async beforeRegisterNodeDef(nodeType, nodeData, _) {
        if (!MANAGED.includes(nodeData.name)) return;

        // === 0. 域名高亮 ===
        const origOnCreated = nodeType.prototype.onNodeCreated;
        nodeType.prototype.onNodeCreated = function() {
            let r = origOnCreated ? origOnCreated.apply(this, arguments) : undefined;
            const el = document.createElement("div");
            el.style.cssText =
                "font-size:11px;line-height:14px;color:#FFD700;font-weight:bold;" +
                "pointer-events:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" +
                "text-shadow:0 0 4px rgba(255,215,0,0.6), 1px 1px 2px rgba(0,0,0,0.8);";
            el.textContent = "解码地址：cishengyixian.com";
            this.addDOMWidget("csyx_domain_tag", "custom", el, {
                getValue() { return ""; }, setValue() {},
                serialize: false,
                computedHeight: 18,
            });
            this._cx_domainEl = el;
            return r;
        };

        // === 1. adjustHeight ===
        nodeType.prototype._cxAdjustHeight = function() {
            const curW = this.size?.[0] || 300;
            let wh = 0;
            for (const wgt of (this.widgets || [])) {
                if (CW.includes(wgt.name) || wgt.name === "csyx_domain_tag") continue;
                if (wgt.type === "hidden") continue;
                wh += (wgt.computedHeight || 22) + 4;
            }
            const imgH = this._cx_imgH || 0;
            const hdr = (typeof LiteGraph !== "undefined" && LiteGraph.NODE_TITLE_HEIGHT) || 26;
            const dh = this._cx_domainEl ? 18 : 0;
            const totalH = hdr + dh + wh + imgH + 4 + 32;
            const curH = this.size?.[1] || 0;
            if (Math.abs(curH - totalH) > 2) {
                this._cx_resizing = true;
                this.size[1] = totalH;
                this._cx_resizing = false;
            }
            if (app.graph) app.graph.setDirtyCanvas(true, true);
        };

        // === onResize ===
        const origOnResize = nodeType.prototype.onResize;
        nodeType.prototype.onResize = function() {
            if (origOnResize) origOnResize.apply(this, arguments);
            if (this._cx_resizing) return;
            if (this._cxImgList && this._cxImgList.length > 0) {
                const hasRatio = this._cxImgList.some(it => it.ratio > 0);
                if (!hasRatio) return;
            }
            this._cx_resizing = true;
            if (this._cxImgList?.length) {
                const nw = this.size?.[0] || 300;
                const nn = this._cxImgList.length;
                if (nn === 1 && this._cx_imgRatio) {
                    this._cx_imgH = Math.ceil(nw / this._cx_imgRatio);
                } else if (nn > 1) {
                    const refW2 = Math.max(50, Math.round((nw - (nn - 1) * 4) / nn));
                    let h = 200;
                    for (const it of this._cxImgList) {
                        if (it.ratio > 0) h = Math.max(h, Math.ceil(refW2 / it.ratio));
                    }
                    this._cx_imgH = h;
                    if (this._cx_imgWidget?.element) {
                        this._cx_imgWidget.element.style.height = h + "px";
                    }
                }
            }
            this._cxAdjustHeight();
            this._cx_resizing = false;
        };

        const origExtra = nodeType.prototype.getExtraMenuOptions;
        nodeType.prototype.getExtraMenuOptions = function(_, options) {
            let r = origExtra ? origExtra.apply(this, arguments) : undefined;
            const node = this;
            if (node._cxImgList && node._cxImgList.length > 0) {
                if (options.length > 0 && options[options.length - 1] !== null) options.push(null);
                for (const imgItem of node._cxImgList) {
                    options.push({ content: `保存图片: ${imgItem.filename}`, callback: () => downloadFile(imgItem.url, imgItem.filename) });
                }
                options.push({ content: "在新窗口打开所有图片", callback: () => {
                    for (const imgItem of node._cxImgList) window.open(imgItem.url, "_blank");
                }});
            }
            return r;
        };

        // === 3. 注册 onExecuted ===
        const origExec = nodeType.prototype.onExecuted;
        nodeType.prototype.onExecuted = function(msg) {
            if (origExec) origExec.apply(this, arguments);
            const mode = msg?.csyx_mode?.[0];
            if (!mode) return;

            this._cxRemoveAll();

            if (msg?.csyx_image?.length > 0) {
                for (let idx = 0; idx < msg.csyx_image.length; idx++) {
                    this._cxAddImgItem(vu({filename: msg.csyx_image[idx], subfolder: "", type: "output"}), idx);
                }
            }
        };

        // === 4. _cxRemoveAll ===
        nodeType.prototype._cxRemoveAll = function() {
            this._cx_cleaning = true;
            this._cxImgList = [];
            this._cx_imgRatio = 0;
            this._cx_imgH = 0;
            this._cx_cleaning = false;

            if (this._cx_imgRo) {
                this._cx_imgRo.disconnect();
                this._cx_imgRo = null;
            }

            if (this.widgets) {
                for (let i = this.widgets.length - 1; i >= 0; i--) {
                    const w = this.widgets[i];
                    if (CW.includes(w.name)) {
                        if (w.element) {
                            if (w.element.parentNode) {
                                w.element.parentNode.removeChild(w.element);
                            }
                            w.element = null;
                        }
                        this.widgets.splice(i, 1);
                    }
                }
            }

            this._cx_imgWidget = null;
            this._cxAdjustHeight();
        };

        // === 5. 图片 DOM widget 渲染 ===
        nodeType.prototype._cxAddImgItem = function(url, index) {
            const node = this;
            const img = new Image();
            img.src = url;

            const item = {
                img: img,
                url: url,
                filename: url.split('/').pop()?.split('?')[0] || "image.png",
                ratio: 0
            };
            if (!this._cxImgList) this._cxImgList = [];
            this._cxImgList.push(item);

            img.onload = () => {
                if (node._cx_cleaning || !node._cxImgList || node._cxImgList.length === 0) return;
                item.ratio = img.naturalWidth / img.naturalHeight;
                node._cx_imgRatio = item.ratio;
                node._cxRefreshImgWidget();
                if (app.canvas) app.canvas.setDirty(true);
            };
            if (img.complete && img.naturalWidth > 0) {
                item.ratio = img.naturalWidth / img.naturalHeight;
                node._cx_imgRatio = item.ratio;
            }
        };

        nodeType.prototype._cxRefreshImgWidget = function() {
            const node = this;
            if (node._cx_cleaning) return;
            if (!node._cxImgList || node._cxImgList.length === 0) return;
            const n = node._cxImgList.length;

            const ready = node._cxImgList.filter(it => it.ratio > 0);
            if (ready.length === 0) return;

            const curW = node.size?.[0] || 300;
            let imgH, initW;
            if (n === 1) {
                const r = ready[0].ratio;
                initW = Math.min(600, Math.max(250, Math.round(r * 250)));
                imgH = Math.ceil(initW / r);
            } else {
                initW = curW;
                const refW2 = Math.max(50, Math.round((curW - (n - 1) * 4) / n));
                imgH = 200;
                for (const it of ready) {
                    if (it.ratio > 0) imgH = Math.max(imgH, Math.ceil(refW2 / it.ratio));
                }
            }

            function calcImgH(nodeW) {
                if (n === 1 && node._cx_imgRatio) return Math.ceil(nodeW / node._cx_imgRatio);
                if (n > 1) {
                    const refW2 = Math.max(50, Math.round((nodeW - (n - 1) * 4) / n));
                    let h = 200;
                    for (const it of node._cxImgList) {
                        if (it.ratio > 0) h = Math.max(h, Math.ceil(refW2 / it.ratio));
                    }
                    return h;
                }
                return 200;
            }

            if (!node._cx_imgWidget) {
                const container = document.createElement("div");
                container.style.cssText = "width:100%;overflow:hidden;border-radius:6px;";

                node._cx_imgWidget = node.addDOMWidget("csyx_iw", "custom", container, {
                    getValue() { return ""; },
                    setValue() {},
                    serialize: false,
                });

                node._cx_imgWidget.computeSize = function() {
                    const nw = node.size?.[0] || 300;
                    const newH = calcImgH(nw);
                    node._cx_imgH = newH;
                    node._cx_imgWidget.computedHeight = newH;
                    if (container) container.style.height = newH + "px";
                    return [nw, newH];
                };

                node._cx_imgRo = new ResizeObserver(entries => {
                    const cw = entries[0].contentRect.width;
                    if (cw <= 0) return;
                    const newH = calcImgH(cw);
                    node._cx_imgH = newH;
                    node._cx_imgWidget.computedHeight = newH;
                    container.style.height = newH + "px";
                    if (app.canvas) app.canvas.setDirty(true);
                });

                container.addEventListener("contextmenu", e => {
                    e.preventDefault();
                    e.stopPropagation();
                    showNodeContextMenu(node, e.clientX, e.clientY);
                });
                container.addEventListener("wheel", e => {
                    e.preventDefault();
                    e.stopPropagation();
                    forwardWheelToCanvas(e);
                });
            }

            const container = node._cx_imgWidget.element;
            if (!container) return;
            container.innerHTML = "";
            container.style.height = imgH + "px";

            if (n === 1) {
                const item = node._cxImgList[0];
                const el = item.img;
                el.style.cssText = "width:100%;height:100%;display:block;object-fit:contain;cursor:pointer;";
                el.addEventListener("click", () => window.open(item.url, "_blank"));
                container.appendChild(el);
            } else {
                container.style.display = "flex";
                container.style.gap = "4px";
                const baseW = node.size?.[0] || initW;
                const refW2 = Math.max(50, Math.round((baseW - (n - 1) * 4) / n));
                for (const item of node._cxImgList) {
                    const wrapper = document.createElement("div");
                    wrapper.className = "csyx-iw-wrap";
                    wrapper.style.cssText = `width:${refW2}px;flex:1;min-width:0;overflow:hidden;border-radius:4px;`;
                    const el = new Image();
                    el.src = item.url;
                    el.style.cssText = "width:100%;height:100%;display:block;object-fit:contain;cursor:pointer;";
                    el.addEventListener("click", () => window.open(item.url, "_blank"));
                    wrapper.appendChild(el);
                    container.appendChild(wrapper);
                }
            }

            if (node._cx_imgRo && container) {
                node._cx_imgRo.observe(container);
            }

            node._cx_imgH = imgH;
            node._cx_imgWidget.computedHeight = imgH;

            let otherH = 0;
            for (const wgt of (node.widgets || [])) {
                if (CW.includes(wgt.name) || wgt.name === "csyx_domain_tag") continue;
                if (wgt.type === "hidden") continue;
                otherH += (wgt.computedHeight || 22) + 4;
            }
            const hdr = (typeof LiteGraph !== "undefined" && LiteGraph.NODE_TITLE_HEIGHT) || 26;
            const dh = node._cx_domainEl ? 18 : 0;
            const totalH = hdr + dh + otherH + imgH + 4 + 32;

            node._cx_resizing = true;
            node.setSize([initW, totalH]);
            node._cx_resizing = false;

            if (app.graph) app.graph.setDirtyCanvas(true, true);
        };
    },
});
