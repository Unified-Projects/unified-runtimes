module.exports = async (context) => {
    return context.res.json({
        ok: true,
        message: "Hello from test function",
        method: context.req.method,
        path: context.req.path,
    });
};
