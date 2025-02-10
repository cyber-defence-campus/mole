import math

from PySide6.QtCore import (QEasingCurve, QLineF,
                            QParallelAnimationGroup, QPointF,
                            QPropertyAnimation, QRectF, Qt)
from PySide6.QtGui import QBrush, QColor, QPainter, QPen, QPolygonF, QFont, QFontMetrics
from PySide6.QtWidgets import (QApplication, QComboBox, QGraphicsItem,
                               QGraphicsObject, QGraphicsScene, QGraphicsView,
                               QStyleOptionGraphicsItem, QVBoxLayout, QWidget)

import networkx as nx
import binaryninja as bn
from ..core.data import Path


class Node(QGraphicsObject):
    """A QGraphicsItem representing node in a graph"""

    def __init__(self, node: bn.MediumLevelILFunction, on_click_callback: callable, get_node_color: callable, parent=None):
        """Node constructor

        Args:
            name (str): Node label
        """
        super().__init__(parent)
        self._node_backing = node
        self._name = f"0x{node.source_function.start:08x}\n{node.source_function.name}"
        self._on_click = on_click_callback
        self._get_node_color = get_node_color
        self._edges = []
        self._padding = 10

        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setCacheMode(QGraphicsItem.CacheMode.DeviceCoordinateCache)

        self._update_rect()

    def _update_rect(self):
        """Update the bounding rectangle to fit the text"""
        font_metrics = QFontMetrics(QFont())
        text_width = font_metrics.horizontalAdvance(self._name)
        text_height = font_metrics.height()
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
        self._on_click(self)
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
        self._graph_scale = 200

        # Map node name to Node object {str=>Node}
        self._nodes_map = {}


    def get_node_color(self, src_node: bn.MediumLevelILFunction, dest_node: bn.MediumLevelILFunction) -> QColor:
        if self._graph.nodes[src_node]["in_path"] and self._graph.nodes[dest_node]["in_path"]:
            # warm, golden yellow
            return QColor("#FFD166")
        else:
            # lava gray
            return QColor("#808588")
    
    def on_click_callback(self, node: Node):
        if self._bv:
            self._bv.navigate(self._bv.view, node.source_function.start)
        else:
            bn.log_error("No BinaryView set")

    def load_graph(self, path: Path):
        self._bv = path.bv
        self._graph = path.call_graph

        self.scene().clear()
        self._nodes_map.clear()

        # Add nodes
        for node in self._graph:
            item = Node(node, self.on_click_callback, self.get_node_color)
            self.scene().addItem(item)
            self._nodes_map[node] = item

        # Add edges
        for a, b in self._graph.edges:
            source = self._nodes_map[a]
            dest = self._nodes_map[b]
            self.scene().addItem(Edge(source, dest, self.get_node_color))

        # layout this bad boy
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


    def load_path(self, path: Path):
        """Load a new graph into the view
        Args:
            path (Path): A Path object
        """
        self.view.load_graph(path)
