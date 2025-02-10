import math

from PySide6.QtCore import (QEasingCurve, QLineF,
                            QParallelAnimationGroup, QPointF,
                            QPropertyAnimation, QRectF, Qt)
from PySide6.QtGui import QAction, QBrush, QColor, QPainter, QPen, QPolygonF, QFont, QFontMetrics
from PySide6.QtWidgets import (QToolBar, QComboBox, QGraphicsItem,
                               QGraphicsObject, QGraphicsScene, QGraphicsView,
                               QStyleOptionGraphicsItem, QVBoxLayout, QWidget)

import networkx as nx
import binaryninja as bn
from ..core.data import Path


class Node(QGraphicsObject):
    """A QGraphicsItem representing node in a graph"""

    def __init__(self, node: bn.MediumLevelILFunction, get_node_text: callable, on_click_callback: callable, get_node_color: callable, parent=None):
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

        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setCacheMode(QGraphicsItem.CacheMode.DeviceCoordinateCache)

        self._update_rect()

    def _update_rect(self):
        """Update the bounding rectangle to fit the text"""
        font_metrics = QFontMetrics(QFont())
        text_width = font_metrics.horizontalAdvance(self._name)
        text_height = font_metrics.height() * (self._name.count('\n') + 1)
        self._rect = QRectF(0, 0, text_width + 2 * self._padding, text_height + 2 * self._padding)

    def boundingRect(self) -> QRectF:
        """Override from QGraphicsItem

        Returns:
            QRect: Return node bounding rect
        """
        return self._rect

    def paint(self, painter: QPainter, option: QStyleOptionGraphicsItem, widget: QWidget = None):
        """Override from QGraphicsItem

        Draw node

        Args:
            painter (QPainter)
            option (QStyleOptionGraphicsItem)
        """
        node_color = self._get_node_color(self._node_backing, self._node_backing)
        painter.setRenderHints(QPainter.RenderHint.Antialiasing)
        painter.setPen(
            QPen(
                node_color.darker(),
                2,
                Qt.PenStyle.SolidLine,
                Qt.PenCapStyle.RoundCap,
                Qt.PenJoinStyle.RoundJoin,
            )
        )
        painter.setBrush(QBrush(node_color))
        painter.drawRect(self.boundingRect())
        painter.setPen(QPen(QColor("#222222")))
        painter.drawText(self.boundingRect(), Qt.AlignmentFlag.AlignCenter, self._name)

    def add_edge(self, edge):
        """Add an edge to this node

        Args:
            edge (Edge)
        """
        self._edges.append(edge)

    def itemChange(self, change: QGraphicsItem.GraphicsItemChange, value):
        """Override from QGraphicsItem

        Args:
            change (QGraphicsItem.GraphicsItemChange)
            value (Any)

        Returns:
            Any
        """
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self._edges:
                edge.adjust()

        return super().itemChange(change, value)

    def mousePressEvent(self, event):
        """Override from QGraphicsItem

        Handle mouse press event

        Args:
            event (QGraphicsSceneMouseEvent)
        """
        self._on_click(self._node_backing)
        super().mousePressEvent(event)


class Edge(QGraphicsItem):
    def __init__(self, source: Node, dest: Node, get_node_color: callable, parent: QGraphicsItem = None):
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

        self._line = QLineF()
        self.setZValue(-1)
        self.adjust()

    def boundingRect(self) -> QRectF:
        """Override from QGraphicsItem

        Returns:
            QRect: Return node bounding rect
        """
        return (
            QRectF(self._line.p1(), self._line.p2())
            .normalized()
            .adjusted(
                -self._tickness - self._arrow_size,
                -self._tickness - self._arrow_size,
                self._tickness + self._arrow_size,
                self._tickness + self._arrow_size,
            )
        )

    def adjust(self):
        """
        Update edge position from source and destination node.
        This method is called from Node::itemChange
        """
        self.prepareGeometryChange()
        self._line = QLineF(
            self._source.pos() + self._source.boundingRect().center(),
            self._dest.pos() + self._dest.boundingRect().center(),
        )

    def _draw_arrow(self, painter: QPainter, start: QPointF, end: QPointF):
        """Draw arrow from start point to end point.

        Args:
            painter (QPainter)
            start (QPointF): start position
            end (QPointF): end position
        """
        # get edge color based on destination node
        painter.setBrush(QBrush(self._get_node_color(self._source._node_backing, self._dest._node_backing)))

        line = QLineF(end, start)

        angle = math.atan2(-line.dy(), line.dx())
        arrow_p1 = line.p1() + QPointF(
            math.sin(angle + math.pi / 3) * self._arrow_size,
            math.cos(angle + math.pi / 3) * self._arrow_size,
        )
        arrow_p2 = line.p1() + QPointF(
            math.sin(angle + math.pi - math.pi / 3) * self._arrow_size,
            math.cos(angle + math.pi - math.pi / 3) * self._arrow_size,
        )

        arrow_head = QPolygonF()
        arrow_head.clear()
        arrow_head.append(line.p1())
        arrow_head.append(arrow_p1)
        arrow_head.append(arrow_p2)
        painter.drawLine(line)
        painter.drawPolygon(arrow_head)

    def _arrow_target(self) -> QPointF:
        """Calculate the position of the arrow taking into account the size of the destination node

        Returns:
            QPointF
        """
        target = self._line.p1()
        center = self._line.p2()
        rect = self._dest.boundingRect()
        vector = target - center
        length = math.sqrt(vector.x() ** 2 + vector.y() ** 2)
        if length == 0:
            return target
        normal = vector / length
        target = QPointF(center.x() + (normal.x() * rect.width() / 2), center.y() + (normal.y() * rect.height() / 2))

        return target

    def paint(self, painter: QPainter, option: QStyleOptionGraphicsItem, widget=None):
        """Override from QGraphicsItem

        Draw Edge. This method is called from Edge.adjust()

        Args:
            painter (QPainter)
            option (QStyleOptionGraphicsItem)
        """

        if self._source and self._dest:
            painter.setRenderHints(QPainter.RenderHint.Antialiasing)

            painter.setPen(
                QPen(
                    QColor(self._get_node_color(self._source._node_backing, self._dest._node_backing)),
                    self._tickness,
                    Qt.PenStyle.SolidLine,
                    Qt.PenCapStyle.RoundCap,
                    Qt.PenJoinStyle.RoundJoin,
                )
            )
            arrow_target = self._arrow_target()
            painter.drawLine(self._line.p1(), arrow_target)
            self._draw_arrow(painter, self._line.p1(), arrow_target)


class GraphView(QGraphicsView):
    def __init__(self, parent=None):
        """GraphView constructor

        This widget can display a directed graph

        Args:
            graph (nx.DiGraph): a networkx directed graph
        """
        super().__init__()
        self._scene = QGraphicsScene()
        self.setScene(self._scene)

        self._graph = None

        # Used to add space between nodes
        # TODO: maybe should be based on average box size of nodes?
        self._graph_scale = 200

        # Map node name to Node object {str=>Node}
        self._nodes_map = {}

        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)

    def center_view(self):
        """Center the view on the scene"""
        self.centerOn(self.scene().itemsBoundingRect().center())

    def zoom_in(self):
        """Zoom in the view"""
        self.scale(1.2, 1.2)

    def zoom_out(self):
        """Zoom out the view"""
        self.scale(1 / 1.2, 1 / 1.2)

    def wheelEvent(self, event):
        """Override from QGraphicsView

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

    def fit_to_window(self):
        """Fit the view to the bounding rectangle of all items"""
        self.fitInView(self.scene().itemsBoundingRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def get_node_color(self, src_node: bn.MediumLevelILFunction, dest_node: bn.MediumLevelILFunction) -> QColor:
        # warm, golden yellow is the default
        highlight_color = QColor("#FFD166") 
        if "snk" in self._graph.nodes[src_node] or "snk" in self._graph.nodes[dest_node]:
            # muted, earthy red
            highlight_color = QColor("#D65A5A")
        if "src" in self._graph.nodes[dest_node] or "src" in self._graph.nodes[dest_node]:
            # soft, warm red
            highlight_color = QColor("#FF9999")

        if self._graph.nodes[src_node]["in_path"] and self._graph.nodes[dest_node]["in_path"]:
            return highlight_color
        else:
            # lava gray
            return QColor("#808588")
    
    def on_click_callback(self, node: Node):
        if self._bv:
            self._bv.navigate(self._bv.view, node.source_function.start)
        else:
            bn.log_error("No BinaryView set")

    def get_node_text(self, node: bn.MediumLevelILFunction) -> str:
        node_text = f"0x{node.source_function.start:08x}\n{node.source_function.name}"
        if "snk" in self._graph.nodes[node]:
            node_text += f"\n{self._graph.nodes[node]['snk']}"
        if "src" in self._graph.nodes[node]:
            node_text += f"\n{self._graph.nodes[node]['src']}"
        return node_text

    def load_graph(self, path: Path):
        self._bv = path.bv
        self._graph = path.call_graph

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

    def layout(self):
        positions = nx.multipartite_layout(self._graph, subset_key="call_level", align="horizontal")

        # Change position of all nodes using an animation
        self.animations = QParallelAnimationGroup()
        for node, pos in positions.items():
            x, y = pos
            x *= self._graph_scale
            y *= self._graph_scale
            item = self._nodes_map[node]

            animation = QPropertyAnimation(item, b"pos")
            animation.setDuration(1000)
            animation.setEndValue(QPointF(x, y))
            animation.setEasingCurve(QEasingCurve.Type.OutExpo)
            self.animations.addAnimation(animation)

        self.animations.start()

class GraphWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self._bv = None
        self._graph = None
        self.view = GraphView()        
        v_layout = QVBoxLayout(self)
        v_layout.addWidget(self.view)

        self.toolbar = QToolBar("Graph Toolbar")
        self.addToolBarActions()
        v_layout.addWidget(self.toolbar)

    def addToolBarActions(self):
        """Add actions to the toolbar"""
        center_action = QAction("Center", self)
        center_action.triggered.connect(self.view.center_view)
        self.toolbar.addAction(center_action)

        zoom_in_action = QAction("Zoom In", self)
        zoom_in_action.triggered.connect(self.view.zoom_in)
        self.toolbar.addAction(zoom_in_action)

        zoom_out_action = QAction("Zoom Out", self)
        zoom_out_action.triggered.connect(self.view.zoom_out)
        self.toolbar.addAction(zoom_out_action)

        fit_action = QAction("Fit", self)
        fit_action.triggered.connect(self.view.fit_to_window)
        self.toolbar.addAction(fit_action)

        reset_action = QAction("Reset", self)
        reset_action.triggered.connect(self.view.layout)
        self.toolbar.addAction(reset_action)

    def load_path(self, path: Path):
        """Load a new graph into the view
        Args:
            path (Path): A Path object
        """
        self.view.load_graph(path)
