import dynamic from 'next/dynamic';

const PolicyReviewPage = dynamic(() => import('../components/policy-review/PolicyReviewPage'), {
    ssr: false,
});

export default PolicyReviewPage;
