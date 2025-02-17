from ..core.data import Path, MediumLevelILInstructionGraph
from typing      import Any
import binaryninja       as bn
import math
import matplotlib.pyplot as plt
import networkx          as nx
import PySide6.QtCore    as qtc
import PySide6.QtGui     as qtui
import PySide6.QtWidgets as qtw


class Node(qtw.QGraphicsObject):
    """A qtw.QGraphicsItem representing node in a graph"""

    def __init__(
            self,
            node: bn.MediumLevelILFunction,
            get_node_text: callable,
            on_click_callback: callable,
            get_node_color: callable,
            parent=None
        ) -> None:
        """Node constructor

        Args:
            name (str): Node label
        """
        super().__init__(parent)
        self._node_backing = node
        self._name = get_node_text(node)
        self._on_click = on_click_callback
        self._get_node_color = get_node_color
        self._edges = []
        self._padding = 5

        self.setFlag(qtw.QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(qtw.QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setCacheMode(qtw.QGraphicsItem.CacheMode.DeviceCoordinateCache)

        self._update_rect()
        return

    def _update_rect(self) -> None:
        """Update the bounding rectangle to fit the text"""
        font_metrics = qtui.QFontMetrics(qtui.QFont())
        text_width = font_metrics.horizontalAdvance(self._name)
        text_height = font_metrics.height() * (self._name.count('\n') + 1)
        self._rect = qtc.QRectF(0, 0, text_width + 2 * self._padding, text_height + 2 * self._padding)
        return

    def boundingRect(self) -> qtc.QRectF:
        """Override from qtw.QGraphicsItem

        Returns:
            QRect: Return node bounding rect
        """
        return self._rect

    def paint(
            self,
            painter: qtui.QPainter,
            option: qtw.QStyleOptionGraphicsItem,
            widget: qtw.QWidget = None
        ) -> None:
        """Override from qtw.QGraphicsItem

        Draw node

        Args:
            painter (qtui.QPainter)
            option (qtw.QStyleOptionGraphicsItem)
        """
        node_color = self._get_node_color(self._node_backing, self._node_backing)
        painter.setRenderHints(qtui.QPainter.RenderHint.Antialiasing)
        painter.setPen(
            qtui.QPen(
                node_color.darker(),
                2,
                qtc.Qt.PenStyle.SolidLine,
                qtc.Qt.PenCapStyle.RoundCap,
                qtc.Qt.PenJoinStyle.RoundJoin,
            )
        )
        painter.setBrush(qtui.QBrush(node_color))
        painter.drawRect(self.boundingRect())
        painter.setPen(qtui.QPen(qtui.QColor("#222222")))
        painter.drawText(self.boundingRect(), qtc.Qt.AlignmentFlag.AlignCenter, self._name)
        return

    def add_edge(self, edge) -> None:
        """Add an edge to this node

        Args:
            edge (Edge)
        """
        self._edges.append(edge)
        return

    def itemChange(self, change: qtw.QGraphicsItem.GraphicsItemChange, value: Any) -> Any:
        """Override from qtw.QGraphicsItem

        Args:
            change (qtw.QGraphicsItem.GraphicsItemChange)
            value (Any)

        Returns:
            Any
        """
        if change == qtw.QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self._edges:
                edge.adjust()

        return super().itemChange(change, value)

    def mouseDoubleClickEvent(self, event: qtw.QGraphicsSceneMouseEvent) -> None:
        """Override from qtw.QGraphicsItem

        Handle mouse double click event

        Args:
            event (qtw.QGraphicsSceneMouseEvent)
        """
        self._on_click(self._node_backing)
        super().mouseDoubleClickEvent(event)
        return


class Edge(qtw.QGraphicsItem):

    def __init__(
            self,
            source: Node,
            dest: Node,
            get_node_color: callable,
            parent: qtw.QGraphicsItem = None
        ) -> None:
        """Edge constructor

        Args:
            source (Node): source node
            dest (Node): destination node
        """
        super().__init__(parent)
        self._source = source
        self._dest = dest
        self._get_node_color = get_node_color
        
        self._tickness = 2
        self._arrow_size = 20

        self._source.add_edge(self)
        self._dest.add_edge(self)

        self._line = qtc.QLineF()
        self.setZValue(-1)
        self.adjust()
        return

    def boundingRect(self) -> qtc.QRectF:
        """Override from qtw.QGraphicsItem

        Returns:
            QRect: Return node bounding rect
        """
        return (
            qtc.QRectF(self._line.p1(), self._line.p2())
            .normalized()
            .adjusted(
                -self._tickness - self._arrow_size,
                -self._tickness - self._arrow_size,
                self._tickness + self._arrow_size,
                self._tickness + self._arrow_size,
            )
        )

    def adjust(self) -> None:
        """
        Update edge position from source and destination node.
        This method is called from Node::itemChange
        """
        self.prepareGeometryChange()
        self._line = qtc.QLineF(
            self._source.pos() + self._source.boundingRect().center(),
            self._dest.pos() + self._dest.boundingRect().center(),
        )
        return

    def _draw_arrow(self, painter: qtui.QPainter, start: qtc.QPointF, end: qtc.QPointF) -> None:
        """Draw arrow from start point to end point.

        Args:
            painter (qtui.QPainter)
            start (qtc.QPointF): start position
            end (qtc.QPointF): end position
        """
        # get edge color based on destination node
        painter.setBrush(qtui.QBrush(self._get_node_color(self._source._node_backing, self._dest._node_backing)))

        line = qtc.QLineF(end, start)

        angle = math.atan2(-line.dy(), line.dx())
        arrow_p1 = line.p1() + qtc.QPointF(
            math.sin(angle + math.pi / 3) * self._arrow_size,
            math.cos(angle + math.pi / 3) * self._arrow_size,
        )
        arrow_p2 = line.p1() + qtc.QPointF(
            math.sin(angle + math.pi - math.pi / 3) * self._arrow_size,
            math.cos(angle + math.pi - math.pi / 3) * self._arrow_size,
        )

        arrow_head = qtui.QPolygonF()
        arrow_head.clear()
        arrow_head.append(line.p1())
        arrow_head.append(arrow_p1)
        arrow_head.append(arrow_p2)
        painter.drawLine(line)
        painter.drawPolygon(arrow_head)
        return

    def _arrow_target(self) -> qtc.QPointF:
        """Calculate the position of the arrow taking into account the size of the destination node

        Returns:
            qtc.QPointF
        """
        target = self._line.p1()
        center = self._line.p2()
        rect = self._dest.boundingRect()
        vector = target - center
        length = math.sqrt(vector.x() ** 2 + vector.y() ** 2)
        if length == 0:
            return target
        normal = vector / length
        target = qtc.QPointF(center.x() + (normal.x() * rect.width() / 2), center.y() + (normal.y() * rect.height() / 2))
        return target

    def paint(
            self,
            painter: qtui.QPainter,
            option: qtw.QStyleOptionGraphicsItem,
            widget=None
        ) -> None:
        """Override from qtw.QGraphicsItem

        Draw Edge. This method is called from Edge.adjust()

        Args:
            painter (qtui.QPainter)
            option (qtw.QStyleOptionGraphicsItem)
        """

        if self._source and self._dest:
            painter.setRenderHints(qtui.QPainter.RenderHint.Antialiasing)

            painter.setPen(
                qtui.QPen(
                    qtui.QColor(self._get_node_color(self._source._node_backing, self._dest._node_backing)),
                    self._tickness,
                    qtc.Qt.PenStyle.SolidLine,
                    qtc.Qt.PenCapStyle.RoundCap,
                    qtc.Qt.PenJoinStyle.RoundJoin,
                )
            )
            arrow_target = self._arrow_target()
            painter.drawLine(self._line.p1(), arrow_target)
            self._draw_arrow(painter, self._line.p1(), arrow_target)
        return


class GraphView(qtw.QGraphicsView):

    def __init__(self, parent=None) -> None:
        """GraphView constructor

        This widget can display a directed graph

        Args:
            graph (nx.DiGraph): a networkx directed graph
        """
        super().__init__()
        self._scene = qtw.QGraphicsScene()
        self.setScene(self._scene)

        self._graph = None

        # Map node name to Node object {str=>Node}
        self._nodes_map = {}

        self.setDragMode(qtw.QGraphicsView.DragMode.ScrollHandDrag)
        return

    def center_view(self) -> None:
        """Center the view on the scene"""
        self.centerOn(self.scene().itemsBoundingRect().center())
        return

    def zoom_in(self) -> None:
        """Zoom in the view"""
        self.scale(1.2, 1.2)
        return

    def zoom_out(self) -> None:
        """Zoom out the view"""
        self.scale(1 / 1.2, 1 / 1.2)
        return

    def wheelEvent(self, event) -> None:
        """Override from qtw.QGraphicsView

        Handle mouse wheel event to zoom in and out

        Args:
            event (QWheelEvent)
        """
        zoom_in_factor = 1.2
        zoom_out_factor = 1 / zoom_in_factor

        if event.angleDelta().y() > 0:
            self.scale(zoom_in_factor, zoom_in_factor)
        else:
            self.scale(zoom_out_factor, zoom_out_factor)
        return

    def fit_to_window(self) -> None:
        """Fit the view to the bounding rectangle of all items"""
        self.fitInView(self.scene().itemsBoundingRect(), qtc.Qt.AspectRatioMode.KeepAspectRatio)
        return

    def get_node_color(
            self,
            src_node: bn.MediumLevelILFunction,
            dest_node: bn.MediumLevelILFunction
        ) -> qtui.QColor:
        # warm, golden yellow is the default
        highlight_color = qtui.QColor("#FFD166") 
        if "snk" in self._graph.nodes[src_node] or "snk" in self._graph.nodes[dest_node]:
            # muted, earthy red
            highlight_color = qtui.QColor("#D65A5A")
        if "src" in self._graph.nodes[dest_node] or "src" in self._graph.nodes[dest_node]:
            # soft, warm red
            highlight_color = qtui.QColor("#FF9999")

        if self._graph.nodes[src_node]["in_path"] and self._graph.nodes[dest_node]["in_path"]:
            return highlight_color
        # lava gray
        return qtui.QColor("#808588")
    
    def on_click_callback(self, node: Node) -> None:
        if self._bv:
            self._bv.navigate(self._bv.view, node.source_function.start)
        else:
            bn.log_error("No BinaryView set")
        return

    def get_node_text(self, node: bn.MediumLevelILFunction) -> str:
        node_text = f"0x{node.source_function.start:08x}\n{node.source_function.name}"
        if "snk" in self._graph.nodes[node]:
            node_text += f"\n{self._graph.nodes[node]['snk']}"
        if "src" in self._graph.nodes[node]:
            node_text += f"\n{self._graph.nodes[node]['src']}"
        return node_text

    def load_graph(self, bv: bn.BinaryView, path: Path, path_id: int) -> None:
        self._bv = bv
        self._graph = path.call_graph
        self.setToolTip(f"Path {path_id:d}")

        self.scene().clear()
        self._nodes_map.clear()

        # Add nodes
        for node in self._graph:
            item = Node(node, self.get_node_text, self.on_click_callback, self.get_node_color)
            self.scene().addItem(item)
            self._nodes_map[node] = item

        # Add edges
        for a, b in self._graph.edges:
            source = self._nodes_map[a]
            dest = self._nodes_map[b]
            self.scene().addItem(Edge(source, dest, self.get_node_color))

        # layout this bad boy
        self.layout()
        # fit the view to the graph once animation is over
        self.animations.finished.connect(self.fit_to_window)
        return

    def layout(self) -> None:
        positions = nx.multipartite_layout(self._graph, subset_key="call_level", align="horizontal")
        
        levels_nodes = {}
        # collect nodes by level
        for node in positions:
            level = self._graph.nodes[node]["call_level"]
            levels_nodes.setdefault(level, []).append(node)

        # calculate the widest level
        max_width = max(sum(self._nodes_map[node].boundingRect().width() for node in nodes) + (len(nodes) - 1) * 20.0 for nodes in levels_nodes.values())

        new_x_positions = {}
        for level, nodes in levels_nodes.items():
            node_count = len(nodes)
            # we use up all the available space
            total_width = sum(self._nodes_map[node].boundingRect().width() for node in nodes)
            # no need to space out the nodes if there is only one node in the level
            spacing = (max_width - total_width) / (node_count - 1) if node_count > 1 else 0
            # if there is only one node in the level, center it
            x_offset = 0 if node_count > 1 else (max_width - total_width) / 2

            for node in nodes:
                new_x_positions[node] = x_offset
                x_offset += self._nodes_map[node].boundingRect().width() + spacing

        vertical_spacing = 200.0
        self.animations = qtc.QParallelAnimationGroup()
        for node, (ox, oy) in positions.items():
            item = self._nodes_map[node]
            animation = qtc.QPropertyAnimation(item, b"pos")
            animation.setDuration(1000)
            animation.setEndValue(qtc.QPointF(new_x_positions[node], oy * vertical_spacing))
            animation.setEasingCurve(qtc.QEasingCurve.Type.OutExpo)
            self.animations.addAnimation(animation)

        self.animations.start()
        return


class GraphWidget(qtw.QWidget):

    def __init__(self, parent=None) -> None:
        super().__init__()
        self._bv = None
        self._graph = None
        self.view = GraphView()        
        v_layout = qtw.QVBoxLayout(self)
        v_layout.addWidget(self.view)

        self.toolbar = qtw.QToolBar("Graph Toolbar")
        self.addToolBarActions()
        v_layout.addWidget(self.toolbar)
        return

    def addToolBarActions(self) -> None:
        """Add actions to the toolbar"""
        center_action = qtui.QAction("Center", self)
        center_action.triggered.connect(self.view.center_view)
        self.toolbar.addAction(center_action)

        zoom_in_action = qtui.QAction("Zoom In", self)
        zoom_in_action.triggered.connect(self.view.zoom_in)
        self.toolbar.addAction(zoom_in_action)

        zoom_out_action = qtui.QAction("Zoom Out", self)
        zoom_out_action.triggered.connect(self.view.zoom_out)
        self.toolbar.addAction(zoom_out_action)

        fit_action = qtui.QAction("Fit", self)
        fit_action.triggered.connect(self.view.fit_to_window)
        self.toolbar.addAction(fit_action)

        reset_action = qtui.QAction("Reset", self)
        reset_action.triggered.connect(self.view.layout)
        self.toolbar.addAction(reset_action)
        return

    def load_path(self, bv: bn.BinaryView, path: Path, path_id: int) -> None:
        """Load a new graph into the view
        Args:
            bv (bn.BinaryView): The BinaryView object
            path (Path): A Path object
            path_id (int): The path's row in the table
        """
        self.view.load_graph(bv, path, path_id)
        return
    
def plot_inst_graph(bv: bn.BinaryView, inst_graph: MediumLevelILInstructionGraph) -> None:
    """
    Plots an instruction graph on a standalone view.

    Args:
        bv (bn.BinaryView): The BinaryView object representing the binary being analyzed.
        inst_graph (MediumLevelILInstructionGraph): The instruction graph

    Returns:
        None
    """
    plt.figure(figsize=(16, 14))
    pos = nx.spring_layout(inst_graph, k=2.1, iterations=50)
    labels = {node: str(node) for node in inst_graph.nodes}
    nx.draw(inst_graph, pos, with_labels=True, labels=labels, node_size=6000, node_color="skyblue", font_size=8, font_weight="bold", edge_color="gray")
    nx.draw_networkx_edge_labels(inst_graph, pos, edge_labels={(u, v): f"{u.address:x}->{v.address:x}" for u, v in inst_graph.edges}, font_size=7)

    def on_click(event):
        if event.inaxes:
            mx, my = event.xdata, event.ydata
            for node, node_pos in pos.items():
                node_x, node_y = node_pos
                # simple distance check
                if (mx - node_x)**2 + (my - node_y)**2 < 0.01:
                    bv.navigate(bv.view, node.address)
                    break

    plt.gcf().canvas.mpl_connect('button_press_event', on_click)
    plt.show()