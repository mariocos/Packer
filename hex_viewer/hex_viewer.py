import sys
import tkinter as tk
from tkinter import filedialog, ttk

import elf_parser

BYTES_PER_LINE = 16
OFFSET_WIDTH = 8
HEX_COL_START = OFFSET_WIDTH + 2
HEX_COL_WIDTH = BYTES_PER_LINE * 3 - 1
ASCII_COL_START = HEX_COL_START + HEX_COL_WIDTH + 2

SELECTION_COLORS = [
    "#e03131",  # red
    "#1971c2",  # blue
    "#2f9e44",  # green
    "#f08c00",  # orange
    "#9c36b5",  # purple
    "#0c8599",  # teal
    "#e64980",  # pink
    "#5c940d",  # olive
]
BLEND_ALPHA = 0.55


def _hex_to_rgb(color):
    color = color.lstrip("#")
    return tuple(int(color[i : i + 2], 16) for i in (0, 2, 4))


def _rgb_to_hex(rgb):
    return "#" + "".join(f"{max(0, min(255, round(c))):02x}" for c in rgb)


def blend_colors(colors):
    canvas = (255, 255, 255)
    for color in colors:
        rgb = _hex_to_rgb(color)
        canvas = tuple(c * BLEND_ALPHA + bg * (1 - BLEND_ALPHA) for c, bg in zip(rgb, canvas))
    return _rgb_to_hex(canvas)


def contrast_color(color):
    r, g, b = _hex_to_rgb(color)
    luminance = 0.299 * r + 0.587 * g + 0.114 * b
    return "black" if luminance > 140 else "white"


def format_hex_dump(data):
    lines = []
    for offset in range(0, len(data), BYTES_PER_LINE):
        chunk = data[offset : offset + BYTES_PER_LINE]

        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(HEX_COL_WIDTH)

        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)

        lines.append(f"{offset:0{OFFSET_WIDTH}x}  {hex_part}  {ascii_part}")

    return "\n".join(lines)


class HexViewer(tk.Tk):
    def __init__(self, path=None):
        super().__init__()
        self.title("Hex Viewer")
        self.geometry("1200x700")

        self.field_ranges = {}

        menu = tk.Menu(self)
        file_menu = tk.Menu(menu, tearoff=0)
        file_menu.add_command(label="Open...", command=self.open_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menu.add_cascade(label="File", menu=file_menu)
        self.config(menu=menu)

        paned = tk.PanedWindow(self, orient="horizontal", sashwidth=4)
        paned.pack(fill="both", expand=True)

        tree_frame = tk.Frame(paned)
        self.tree = ttk.Treeview(
            tree_frame, columns=("value",), show="tree headings", selectmode="extended"
        )
        self.tree.heading("#0", text="Field")
        self.tree.heading("value", text="Value")
        self.tree.column("#0", width=220, stretch=False)
        self.tree.column("value", width=380, stretch=True)
        self.tree.pack(side="left", fill="both", expand=True)

        tree_scroll = tk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        tree_scroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=tree_scroll.set)

        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        paned.add(tree_frame, width=450)

        text_frame = tk.Frame(paned)
        self.text = tk.Text(text_frame, wrap="none", font=("Courier New", 11))
        self.text.pack(side="left", fill="both", expand=True)

        text_scroll = tk.Scrollbar(text_frame, orient="vertical", command=self.text.yview)
        text_scroll.pack(side="right", fill="y")
        self.text.configure(yscrollcommand=text_scroll.set)

        paned.add(text_frame)

        if path:
            self.load_file(path)

    def open_file(self):
        path = filedialog.askopenfilename(title="Select a binary file")
        if path:
            self.load_file(path)

    def load_file(self, path):
        with open(path, "rb") as f:
            data = f.read()

        self.title(f"Hex Viewer - {path}")

        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", format_hex_dump(data))
        self.text.config(state="disabled")

        self.tree.delete(*self.tree.get_children())
        self.field_ranges = {}

        elf_info = elf_parser.parse_elf(data)
        if elf_info:
            self.build_tree(elf_info)
        else:
            self.tree.insert("", "end", text="(not a recognized ELF64 file)")

    def build_tree(self, elf_info):
        header_root = self.tree.insert("", "end", text="ELF Header", open=True)
        self.field_ranges[header_root] = (0, elf_info["header_size"])
        for f in elf_info["header"]:
            self._insert_field(header_root, f)

        ph_root = self.tree.insert("", "end", text="Program Headers (Segments)", open=True)
        for ph in elf_info["program_headers"]:
            label = f"Segment {ph['index']} ({ph['type_name']})"
            seg_node = self.tree.insert(ph_root, "end", text=label)
            self.field_ranges[seg_node] = (ph["seg_offset"], ph["seg_filesz"])
            for f in ph["fields"]:
                self._insert_field(seg_node, f)

        sh_root = self.tree.insert("", "end", text="Section Headers", open=True)
        for sh in elf_info["section_headers"]:
            label = f"Section {sh['index']}: {sh['name']}"
            sec_node = self.tree.insert(sh_root, "end", text=label)
            self.field_ranges[sec_node] = (sh["seg_offset"], sh["seg_filesz"])
            for f in sh["fields"]:
                self._insert_field(sec_node, f)

    def _insert_field(self, parent, field):
        iid = self.tree.insert(parent, "end", text=field["name"], values=(field["display"],))
        self.field_ranges[iid] = (field["offset"], field["size"])

    def on_tree_select(self, event):
        selection = self.tree.selection()
        ranges = []
        for i, item in enumerate(selection):
            rng = self.field_ranges.get(item)
            if not rng:
                continue
            offset, size = rng
            color = SELECTION_COLORS[i % len(SELECTION_COLORS)]
            ranges.append((offset, size, color))
        self.highlight_ranges(ranges)

    def _iter_line_spans(self, offset, size):
        if size <= 0:
            return
        end = offset + size
        start_line = offset // BYTES_PER_LINE
        end_line = (end - 1) // BYTES_PER_LINE

        for line in range(start_line, end_line + 1):
            line_byte_start = line * BYTES_PER_LINE
            col_start = max(offset, line_byte_start) - line_byte_start
            col_end = min(end, line_byte_start + BYTES_PER_LINE) - line_byte_start

            hex_start = HEX_COL_START + col_start * 3
            hex_end = HEX_COL_START + col_end * 3 - 1
            ascii_start = ASCII_COL_START + col_start
            ascii_end = ASCII_COL_START + col_end

            yield line, hex_start, hex_end, ascii_start, ascii_end

    def highlight_ranges(self, ranges):
        for tag in self.text.tag_names():
            if tag.startswith("sel_"):
                self.text.tag_remove(tag, "1.0", "end")
                self.text.tag_delete(tag)

        valid = [(offset, size, color) for offset, size, color in ranges if size > 0]
        if not valid:
            return

        boundaries = sorted({b for offset, size, _ in valid for b in (offset, offset + size)})

        first_line = None
        tag_index = 0
        for start, stop in zip(boundaries, boundaries[1:]):
            covering = [color for offset, size, color in valid if offset <= start and offset + size >= stop]
            if not covering:
                continue

            tag_name = f"sel_{tag_index}"
            tag_index += 1
            fused = blend_colors(covering)
            self.text.tag_configure(tag_name, background=fused, foreground=contrast_color(fused))

            for line, hex_start, hex_end, ascii_start, ascii_end in self._iter_line_spans(start, stop - start):
                self.text.tag_add(tag_name, f"{line + 1}.{hex_start}", f"{line + 1}.{hex_end}")
                self.text.tag_add(tag_name, f"{line + 1}.{ascii_start}", f"{line + 1}.{ascii_end}")
                if first_line is None:
                    first_line = line + 1

        if first_line is not None:
            self.text.see(f"{first_line}.0")


if __name__ == "__main__":
    initial_path = sys.argv[1] if len(sys.argv) > 1 else None
    app = HexViewer(initial_path)
    app.mainloop()
