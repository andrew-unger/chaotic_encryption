use rayon::prelude::*;

/// Chen System - A modified Lorenz system with stronger chaotic behavior
pub struct ChenSystem {
    x: f64,
    y: f64,
    z: f64,
    a: f64,
    b: f64,
    c: f64,
    dt: f64,
}

impl ChenSystem {
    pub fn new(x: f64, y: f64, z: f64, a: f64, b: f64, c: f64, dt: f64) -> Self {
        ChenSystem { x, y, z, a, b, c, dt }
    }

    pub fn iterate(&mut self) -> f64 {
        // Chen system of differential equations
        let dx = self.a * (self.y - self.x);
        let dy = (self.c - self.a) * self.x - self.x * self.z + self.c * self.y;
        let dz = self.x * self.y - self.b * self.z;
        
        // Update using Euler method
        self.x += dx * self.dt;
        self.y += dy * self.dt;
        self.z += dz * self.dt;
        
        // Normalize to [0,1] using a simple transformation
        (self.x.abs() + self.y.abs() + self.z.abs()).fract()
    }
    
    pub fn evolve(&mut self) {
        self.a = (self.a + self.iterate()).fract() + 35.0; // Keep a around 35-36
        self.b = (self.b + self.iterate()).fract() + 3.0;  // Keep b around 3-4
        self.c = (self.c + self.iterate()).fract() + 28.0; // Keep c around 28-29
    }
}

/// Tent Map - A simple but effective discrete chaotic map
pub struct TentMap {
    x: f64,
    mu: f64,
}

impl TentMap {
    pub fn new(x: f64, mu: f64) -> Self {
        TentMap { x, mu }
    }

    pub fn iterate(&mut self) -> f64 {
        // Tent map iteration
        if self.x < 0.5 {
            self.x = self.mu * self.x;
        } else {
            self.x = self.mu * (1.0 - self.x);
        }
        
        self.x
    }

    pub fn evolve(&mut self) {
        self.mu = (self.mu + self.iterate()).fract() + 1.5; // Keep mu around 1.5-2.5
        
        // Ensure mu doesn't exceed 2.0 for bounded behavior
        if self.mu > 2.0 {
            self.mu = 2.0;
        }
    }
}

/// Rabinovich-Fabrikant System - Complex multi-scroll attractor
pub struct RabinovichFabrikantSystem {
    x: f64,
    y: f64,
    z: f64,
    alpha: f64,
    gamma: f64,
    dt: f64,
}

impl RabinovichFabrikantSystem {
    pub fn new(x: f64, y: f64, z: f64, alpha: f64, gamma: f64, dt: f64) -> Self {
        RabinovichFabrikantSystem { x, y, z, alpha, gamma, dt }
    }

    pub fn iterate(&mut self) -> f64 {
        // Rabinovich-Fabrikant system of differential equations
        let dx = self.y * (self.z - 1.0 + self.x * self.x) + self.gamma * self.x;
        let dy = self.x * (3.0 * self.z + 1.0 - self.x * self.x) + self.gamma * self.y;
        let dz = -2.0 * self.z * (self.alpha + self.x * self.y);
        
        // Update using Euler method
        self.x += dx * self.dt;
        self.y += dy * self.dt;
        self.z += dz * self.dt;
        
        // Normalize to [0,1] using a simple transformation
        (self.x.abs() + self.y.abs() + self.z.abs()).fract()
    }
    
    pub fn evolve(&mut self) {
        self.alpha = (self.alpha + self.iterate()).fract() + 0.1; // Keep alpha around 0.1-1.1
        self.gamma = (self.gamma + self.iterate()).fract() + 0.1; // Keep gamma around 0.1-1.1
    }
}

pub fn chen_warmup(c: &mut ChenSystem, rounds: usize) {
    for _ in 0..rounds {
        c.iterate();
    }
}

pub fn tent_warmup(t: &mut TentMap, rounds: usize) {
    for _ in 0..rounds {
        t.iterate();
    }
}

pub fn rf_warmup(rf: &mut RabinovichFabrikantSystem, rounds: usize) {
    for _ in 0..rounds {
        rf.iterate();
    }
}

// Generate interlaced chaotic sequence from three sources
pub fn interlaced_chaos_sequence(
    chen: &mut ChenSystem, 
    tent: &mut TentMap, 
    rf: &mut RabinovichFabrikantSystem, 
    len: usize
) -> Vec<f64> {
    let mut result = vec![0.0f64; len];
    
    for i in 0..len {
        let c_val = chen.iterate();
        let t_val = tent.iterate();
        let rf_val = rf.iterate();
        
        // Combine the three chaotic values with different weights
        // RF system gets slightly higher weight for better diffusion
        result[i] = ((c_val * 0.3) + (t_val * 0.3) + (rf_val * 0.4)).fract();
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