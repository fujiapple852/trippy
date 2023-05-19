use ratatui::style::Color;
use ratatui::widgets::canvas::{Painter, Shape};

#[derive(Debug, Clone)]
pub struct CircleWidget {
    pub x: f64,
    pub y: f64,
    pub radius: f64,
    pub color: Color,
}

impl CircleWidget {
    pub fn new(x: f64, y: f64, radius: f64, color: Color) -> Self {
        Self {
            x,
            y,
            radius,
            color,
        }
    }
}

impl Shape for CircleWidget {
    fn draw(&self, painter: &mut Painter<'_, '_>) {
        for angle in 0..360 {
            let radians = f64::from(angle).to_radians();
            let circle_x = self.radius.mul_add(radians.cos(), self.x);
            let circle_y = self.radius.mul_add(radians.sin(), self.y);
            if let Some((x, y)) = painter.get_point(circle_x, circle_y) {
                painter.paint(x, y, self.color);
            }
        }
    }
}
