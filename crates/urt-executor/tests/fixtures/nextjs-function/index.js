// Next.js-style API route handler for benchmarking
// Simulates common Next.js patterns: JSON parsing, headers, response formatting

module.exports = async (context) => {
    const { req, res } = context;

    // Parse request body if present
    let body = {};
    if (req.body) {
        try {
            body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
        } catch (e) {
            body = { raw: req.body };
        }
    }

    // Route handling similar to Next.js API routes
    const path = req.path || '/';
    const method = req.method || 'GET';

    // Simulate different endpoints
    switch (path) {
        case '/api/health':
            return res.json({
                status: 'healthy',
                timestamp: Date.now(),
                uptime: process.uptime()
            });

        case '/api/data':
            // Simulate data processing workload
            const items = [];
            for (let i = 0; i < 100; i++) {
                items.push({
                    id: i,
                    name: `Item ${i}`,
                    value: Math.random() * 1000,
                    timestamp: Date.now()
                });
            }
            return res.json({
                success: true,
                count: items.length,
                data: items
            });

        case '/api/echo':
            return res.json({
                method,
                path,
                headers: req.headers,
                body,
                timestamp: Date.now()
            });

        case '/api/compute':
            // CPU-bound workload simulation
            let result = 0;
            for (let i = 0; i < 10000; i++) {
                result += Math.sqrt(i) * Math.sin(i);
            }
            return res.json({
                success: true,
                result: result.toFixed(4),
                iterations: 10000
            });

        default:
            // Default SSR-like response
            return res.json({
                ok: true,
                message: "Next.js benchmark function",
                method,
                path,
                query: req.query || {},
                timestamp: Date.now(),
                runtime: {
                    node: process.version,
                    platform: process.platform,
                    arch: process.arch
                }
            });
    }
};
