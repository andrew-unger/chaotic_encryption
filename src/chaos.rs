use rayon::prelude::*;

pub struct HenonMap {
    x: f64,
    y: f64,
    a: f64,
    b: f64,
}

impl HenonMap {
    pub fn new(x: f64, y: f64, a: f64, b: f64) -> Self {
        HenonMap { x, y, a, b }
    }

    pub fn iterate(&mut self) -> f64 {
        let next_x = 1.0 - self.a * self.x.powi(2) + self.y;
        let next_y = self.b * self.x;
        self.x = next_x;
        self.y = next_y;
        self.x
    }

    pub fn evolve(&mut self) {
        self.a = (self.a + self.iterate()).fract();
        self.b = (self.b + self.iterate()).fract();
    }
}

pub fn henon_warmup(h: &mut HenonMap, rounds: usize) {
    for _ in 0..rounds {
        h.iterate();
    }
}

pub fn logistic_map(mut x: f64, r: f64, len: usize) -> Vec<f64> {
    let mut result = vec![0.0f64; len];
    for i in 0..len {
        x = r * x * (1.0 - x);
        result[i] = x;
    }
    result
}

pub fn chaotic_permutation(input: &[u8], chaos_sequence: &[f64]) -> Vec<u8> {
    let mut indices: Vec<(usize, f64)> = chaos_sequence.iter().cloned().enumerate().collect();
    indices.par_sort_unstable_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    indices.par_iter().map(|(orig_idx, _)| input[*orig_idx]).collect()
}

pub fn inverse_chaotic_permutation(input: &[u8], chaos_sequence: &[f64]) -> Vec<u8> {
    let mut indices: Vec<(usize, f64)> = chaos_sequence.iter().cloned().enumerate().collect();
    indices.par_sort_unstable_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    let mut inverse = vec![0usize; input.len()];
    for (i, (orig_idx, _)) in indices.iter().enumerate() {
        inverse[*orig_idx] = i;
    }
    (0..input.len()).into_par_iter().map(|i| input[inverse[i]]).collect()
}