const express = require('express');
const router = express.Router();
const { check, validationResult, body } = require('express-validator/check');
const auth = require('../../middleware/auth');
const User = require('../../models/User');
const Post = require('../../models/Post');

// @route POST api/posts
// @desc Create a post
// @access Private
router.post('/', [auth, [
    check('text', 'Text is required').not().isEmpty()
]], async (req, res) => {
    const error = validationResult(req);
    if (!error.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {

        const user = await User.findById(req.user.id).select('-password');

        const newPost = new Post({
            text: req.body.text,
            name: user.name,
            avatar: user.avatar,
            user: req.user.id
        });
        const post = await newPost.save();
        res.json(post);

    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server Error');
    }

});


// @route GET api/posts
// @desc Get all post
// @access Private
router.get('/', auth, async (req, res) => {
    try {
        var posts = await Post.find().sort({ date: -1 });
        res.json(posts);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// @route Delete api/posts/:id
// @desc Delete post by ID
// @access Private
router.delete('/:id', auth, async (req, res) => {
    try {
        var post = await Post.findById(req.params.id);

        // Check post has available
        if (!post) return res.status(404).json({ msg: 'Post not found' });

        // Check user
        if (post.user.toString() !== req.user.id) return res.status(401).json({ msg: 'User not authorized' });

        await post.remove();
    } catch (err) {

        console.error(err.message);
        if (err.kind === 'ObjectId') return res.status(404).json({ msg: 'Page not found' });

        res.status(500).send('Server error');
    }
});


// @route GET api/posts/:id
// @desc Get post by ID
// @access Private
router.get('/:id', auth, async (req, res) => {
    try {
        var posts = await Post.findById(req.params.id);

        if (!posts) return res.status(404).json({ msg: 'Post not found' });

        res.json(posts);
    } catch (err) {

        console.error(err.message);
        if (err.kind === 'ObjectId') return res.status(404).json({ msg: 'Page not found' });

        res.status(500).send('Server error');
    }
});

// @route PUT api/posts/like/:id
// @desc Like a post
// @access Private
router.put('/like/:id', auth, async (req, res) => {
    try {
        var posts = await Post.findById(req.params.id);

        // Check if the post has already been liked
        if (posts.likes.filter(like => like.user.toString() === req.user.id).length > 0) {
            return res.status(400).json({ msg: 'Post already liked' });
        }

        posts.likes.unshift({ user: req.user.id });
        await posts.save();

    } catch (err) {

        console.error(err.message);
        if (err.kind === 'ObjectId') return res.status(404).json({ msg: 'Page not found' });

        res.status(500).send('Server error');
    }
});


// @route PUT api/posts/unlike/:id
// @desc Unlike a post
// @access Private
router.put('/unlike/:id', auth, async (req, res) => {
    try {
        var posts = await Post.findById(req.params.id);

        // Check if the post has already been liked
        if (posts.likes.filter(like => like.user.toString() === req.user.id).length === 0) {
            return res.status(400).json({ msg: 'Post has not yet been liked' });
        }

        // Get remove index
        const removeIndex = posts.likes.map(like => like.user.toString()).indexOf(req.user.id);
        posts.likes.splice(removeIndex, 1)
        await posts.save();
        res.json(posts.likes);

    } catch (err) {

        console.error(err.message);
        if (err.kind === 'ObjectId') return res.status(404).json({ msg: 'Page not found' });

        res.status(500).send('Server error');
    }
});


// @route PUT api/posts/comment/:id
// @desc Comment on a post
// @access Private
router.post('/comment/:id', [auth, [
    check('text', 'Text is required').not().isEmpty()
]], async (req, res) => {

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        const user = await User.findById(req.user.id).select('-password');
        const post = await Post.findById(req.params.id);

        const newComment = {
            text: req.body.text,
            name: user.name,
            avatar: user.avatar,
            user: req.user.id
        }
        post.comments.unshift(newComment);

        post.save();
        return res.json(post);

    } catch (err) {

        console.error(err.message);
        if (err.kind === 'ObjectId') return res.status(404).json({ msg: 'Page not found' });

        res.status(500).send('Server error');
    }
});


// @route PUT api/posts/comment/:id/:_comment_id
// @desc Delete on a post
// @access Private
router.delete('/comment/:id/:comment_id', auth, async (req, res) => {

    try {
        const post = await Post.findById(req.params.id);

        // Pull out comment
        const comment = post.comments.find(cm => cm.id === req.params.comment_id);

        // Make sure comment exist
        if (!comment) return res.status(400).json({ msg: 'Comment does not exist' });

        // Check user
        if (comment.user.toString() !== req.user.id) return res.status(401).json({ msg: 'User not authorized' });

        // Get remove index
        const removeIndex = post.comments.map(cmt => cmt.user.toString()).indexOf(req.user.id);
        post.comments.splice(removeIndex, 1);

        await post.save()

        return res.json(post);

    } catch (err) {

        console.error(err.message);
        if (err.kind === 'ObjectId') return res.status(404).json({ msg: 'Page not found' });

        res.status(500).send('Server error');
    }
});



module.exports = router;